"""Company Data MCP server (Stage 1, slice 3).

A mock system of record: invoices, payments, beneficiaries, customers, employees, payroll.
Nine tools, matching `docs/permission-matrix.md`.

This server is deliberately UNPROTECTED. It enforces business rules a real system would
(an invoice must exist, only approved invoices can be paid, an account number must be
well-formed) but none of the security rules: no limits on `list_invoices` or `export_records`,
no approval for large payments, no restriction on sensitive tables. Those belong to the
gateway, and the unprotected baseline (slice 7) shows what happens without it.

All state is held in memory and starts fresh from the seed file, so changes reset on restart.
"""

from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field

from core.seed_models import CompanyDataSeed, Invoice, InvoiceStatus, Payment
from mcp_servers.runner import serve

ExportTable = Literal["invoices", "customers", "employees", "payroll"]
Limit = Annotated[int, Field(ge=1)]
PositiveAmount = Annotated[float, Field(gt=0)]
AccountNumber = Annotated[str, Field(pattern=r"^\d{8,12}$")]

DEFAULT_LIST_LIMIT = 20
DEFAULT_PORT = 9001
DEFAULT_SEED_FILE = "data/seed/company_data.json"


def _dump(record: BaseModel) -> dict[str, Any]:
    return record.model_dump(mode="json")


def _last4(account_number: str) -> str:
    return account_number[-4:]


class CompanyData:
    """In-memory state and business logic. Raises `ToolError` for anticipated failures."""

    def __init__(self, seed: CompanyDataSeed, today: Callable[[], date] = date.today) -> None:
        # Copies, so two servers built from the same seed never share state.
        self._beneficiaries = {b.beneficiary_id: b for b in seed.beneficiaries}
        self._invoices = {i.invoice_id: i for i in seed.invoices}
        self._payments = list(seed.payments)
        self._customers = {c.customer_id: c for c in seed.customers}
        self._employees = {e.employee_id: e for e in seed.employees}
        self._payroll = {p.employee_id: p for p in seed.payroll}
        self._today = today

    # ---- invoices and payments

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        return _dump(self._invoice(invoice_id))

    def list_invoices(self, status: InvoiceStatus | None, limit: int) -> dict[str, Any]:
        matching = [i for i in self._invoices.values() if status is None or i.status == status]
        return {
            "count": len(matching[:limit]),
            "total_matching": len(matching),
            "invoices": [_dump(i) for i in matching[:limit]],
        }

    def get_payment_status(self, invoice_id: str) -> dict[str, Any]:
        invoice = self._invoice(invoice_id)
        payments = [p for p in self._payments if p.invoice_id == invoice_id]
        return {
            "invoice_id": invoice_id,
            "invoice_status": invoice.status,
            "payment_status": payments[-1].status if payments else "none",
            "payments": [_dump(p) for p in payments],
        }

    def initiate_payment(self, invoice_id: str, amount: float) -> dict[str, Any]:
        invoice = self._invoice(invoice_id)
        if invoice.status != "approved":
            raise ToolError(
                f"Invoice {invoice_id} is {invoice.status}; only approved invoices can be paid"
            )
        if any(
            p.invoice_id == invoice_id and p.status in {"initiated", "completed"}
            for p in self._payments
        ):
            raise ToolError(f"Invoice {invoice_id} already has a payment")
        if round(amount, 2) > round(invoice.amount, 2):
            raise ToolError(f"Amount {amount:.2f} exceeds the invoice amount {invoice.amount:.2f}")
        payment = Payment(
            payment_id=f"PAY-{len(self._payments) + 1:04d}",
            invoice_id=invoice_id,
            amount=round(amount, 2),
            status="initiated",
            created_date=self._today(),
        )
        self._payments.append(payment)
        return _dump(payment)

    # ---- beneficiaries

    def update_beneficiary_bank_details(
        self, beneficiary_id: str, account_number: str
    ) -> dict[str, Any]:
        beneficiary = self._beneficiaries.get(beneficiary_id)
        if beneficiary is None:
            raise ToolError(f"Beneficiary {beneficiary_id} not found")
        self._beneficiaries[beneficiary_id] = beneficiary.model_copy(
            update={"account_number": account_number}
        )
        # Only the last four digits are echoed back, never the full account number.
        return {
            "beneficiary_id": beneficiary_id,
            "previous_account_last4": _last4(beneficiary.account_number),
            "new_account_last4": _last4(account_number),
            "status": "updated",
        }

    # ---- customers, employees, payroll

    def get_customer_record(self, customer_id: str) -> dict[str, Any]:
        customer = self._customers.get(customer_id)
        if customer is None:
            raise ToolError(f"Customer {customer_id} not found")
        return _dump(customer)

    def get_employee_record(self, employee_id: str) -> dict[str, Any]:
        employee = self._employees.get(employee_id)
        if employee is None:
            raise ToolError(f"Employee {employee_id} not found")
        return _dump(employee)

    def read_payroll(self, employee_id: str) -> dict[str, Any]:
        record = self._payroll.get(employee_id)
        if record is None:
            raise ToolError(f"No payroll record for employee {employee_id}")
        return _dump(record)

    # ---- bulk export

    def export_records(self, table: ExportTable, limit: int) -> dict[str, Any]:
        tables: dict[str, list[BaseModel]] = {
            "invoices": list(self._invoices.values()),
            "customers": list(self._customers.values()),
            "employees": list(self._employees.values()),
            "payroll": list(self._payroll.values()),
        }
        rows = tables[table][:limit]
        return {"table": table, "count": len(rows), "rows": [_dump(r) for r in rows]}

    # ---- helpers

    def _invoice(self, invoice_id: str) -> Invoice:
        invoice = self._invoices.get(invoice_id)
        if invoice is None:
            raise ToolError(f"Invoice {invoice_id} not found")
        return invoice


def create_server(seed: CompanyDataSeed, today: Callable[[], date] = date.today) -> MCPServer:
    data = CompanyData(seed, today)
    server = MCPServer("company-data")

    @server.tool()
    def get_invoice(invoice_id: str) -> dict[str, Any]:
        """Read one invoice by its id (for example INV-0001)."""
        return data.get_invoice(invoice_id)

    @server.tool()
    def list_invoices(
        status: InvoiceStatus | None = None, limit: Limit = DEFAULT_LIST_LIMIT
    ) -> dict[str, Any]:
        """List invoices, optionally only those with a given status. Returns at most `limit`."""
        return data.list_invoices(status, limit)

    @server.tool()
    def get_payment_status(invoice_id: str) -> dict[str, Any]:
        """Read the payment status of one invoice."""
        return data.get_payment_status(invoice_id)

    @server.tool()
    def initiate_payment(invoice_id: str, amount: PositiveAmount) -> dict[str, Any]:
        """Start a payment for an approved invoice (mock). Amount is in USD."""
        return data.initiate_payment(invoice_id, amount)

    @server.tool()
    def update_beneficiary_bank_details(
        beneficiary_id: str, account_number: AccountNumber
    ) -> dict[str, Any]:
        """Change the bank account number of a payee (mock)."""
        return data.update_beneficiary_bank_details(beneficiary_id, account_number)

    @server.tool()
    def get_customer_record(customer_id: str) -> dict[str, Any]:
        """Read one customer record."""
        return data.get_customer_record(customer_id)

    @server.tool()
    def export_records(table: ExportTable, limit: Limit) -> dict[str, Any]:
        """Bulk export up to `limit` rows of a table: invoices, customers, employees or payroll."""
        return data.export_records(table, limit)

    @server.tool()
    def get_employee_record(employee_id: str) -> dict[str, Any]:
        """Read one employee record (contains personal data)."""
        return data.get_employee_record(employee_id)

    @server.tool()
    def read_payroll(employee_id: str) -> dict[str, Any]:
        """Read the payroll record of one employee (contains salary and bank details)."""
        return data.read_payroll(employee_id)

    return server


def main(argv: list[str] | None = None) -> int:
    return serve(
        description="Company Data MCP server (mock, unprotected)",
        model=CompanyDataSeed,
        create_server=create_server,
        default_seed_file=Path(DEFAULT_SEED_FILE),
        default_port=DEFAULT_PORT,
        argv=argv,
    )
