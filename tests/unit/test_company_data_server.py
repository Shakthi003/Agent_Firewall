"""Tests for the Company Data MCP server (mcp_servers/company_data/server.py)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from core.seed_generator import (
    PLANTED_AT_LIMIT_INVOICE_ID,
    PLANTED_BENEFICIARY_ACCOUNT,
    PLANTED_BENEFICIARY_ID,
    PLANTED_LARGE_INVOICE_ID,
    PLANTED_OVER_LIMIT_INVOICE_ID,
    generate_company_data,
)
from core.seed_models import CompanyDataSeed
from mcp_servers.company_data.server import CompanyData, create_server, main

EXPECTED_TOOLS = {
    "get_invoice",
    "list_invoices",
    "get_payment_status",
    "initiate_payment",
    "update_beneficiary_bank_details",
    "get_customer_record",
    "export_records",
    "get_employee_record",
    "read_payroll",
}
FIXED_TODAY = date(2026, 2, 1)


@pytest.fixture(scope="module")
def seed() -> CompanyDataSeed:
    return generate_company_data()


@pytest.fixture
def data(seed: CompanyDataSeed) -> CompanyData:
    return CompanyData(seed, today=lambda: FIXED_TODAY)


@pytest.fixture
def client(seed: CompanyDataSeed) -> Client:
    return Client(create_server(seed, today=lambda: FIXED_TODAY))


# ------------------------------------------------------------------ business logic


def test_get_invoice_returns_the_planted_invoice(data: CompanyData) -> None:
    invoice = data.get_invoice(PLANTED_LARGE_INVOICE_ID)
    assert invoice["amount"] == 12000.0
    assert invoice["beneficiary_id"] == PLANTED_BENEFICIARY_ID


def test_get_invoice_unknown_id_is_a_tool_error(data: CompanyData) -> None:
    with pytest.raises(ToolError, match="INV-9999 not found"):
        data.get_invoice("INV-9999")


def test_list_invoices_respects_limit_and_status(data: CompanyData) -> None:
    result = data.list_invoices("paid", 5)
    assert result["count"] == 5
    assert result["total_matching"] > 5
    assert all(i["status"] == "paid" for i in result["invoices"])


def test_list_invoices_has_no_security_limit(data: CompanyData) -> None:
    """The server is unprotected on purpose: the 50-row cap is the gateway's job."""
    assert data.list_invoices(None, 300)["count"] == 300


def test_payment_status_for_unpaid_planted_invoice(data: CompanyData) -> None:
    result = data.get_payment_status(PLANTED_LARGE_INVOICE_ID)
    assert result["payment_status"] == "none"
    assert result["payments"] == []


def test_initiate_payment_creates_a_payment(data: CompanyData) -> None:
    payment = data.initiate_payment(PLANTED_LARGE_INVOICE_ID, 12000.0)
    assert payment["status"] == "initiated"
    assert payment["created_date"] == FIXED_TODAY.isoformat()
    assert data.get_payment_status(PLANTED_LARGE_INVOICE_ID)["payment_status"] == "initiated"


def test_initiate_payment_has_no_security_threshold(data: CompanyData) -> None:
    """12,000 USD goes straight through: the approval rule is the gateway's job."""
    assert data.initiate_payment(PLANTED_LARGE_INVOICE_ID, 12000.0)["amount"] == 12000.0


def test_initiate_payment_boundary_invoices_work(data: CompanyData) -> None:
    data.initiate_payment(PLANTED_AT_LIMIT_INVOICE_ID, 5000.0)
    data.initiate_payment(PLANTED_OVER_LIMIT_INVOICE_ID, 5000.01)


def test_cannot_pay_the_same_invoice_twice(data: CompanyData) -> None:
    data.initiate_payment(PLANTED_LARGE_INVOICE_ID, 100.0)
    with pytest.raises(ToolError, match="already has a payment"):
        data.initiate_payment(PLANTED_LARGE_INVOICE_ID, 100.0)


def test_cannot_pay_more_than_the_invoice(data: CompanyData) -> None:
    with pytest.raises(ToolError, match="exceeds the invoice amount"):
        data.initiate_payment(PLANTED_LARGE_INVOICE_ID, 12000.01)


def test_cannot_pay_an_unapproved_invoice(data: CompanyData, seed: CompanyDataSeed) -> None:
    pending = next(i for i in seed.invoices if i.status == "pending")
    with pytest.raises(ToolError, match="only approved invoices"):
        data.initiate_payment(pending.invoice_id, 10.0)


def test_update_bank_details_changes_account_and_masks_the_echo(data: CompanyData) -> None:
    result = data.update_beneficiary_bank_details(PLANTED_BENEFICIARY_ID, "9988776655")
    assert result["previous_account_last4"] == PLANTED_BENEFICIARY_ACCOUNT[-4:]
    assert result["new_account_last4"] == "6655"
    # The full account numbers are never echoed back.
    assert "9988776655" not in json.dumps(result)
    assert PLANTED_BENEFICIARY_ACCOUNT not in json.dumps(result)


def test_update_bank_details_unknown_beneficiary(data: CompanyData) -> None:
    with pytest.raises(ToolError, match="BEN-999 not found"):
        data.update_beneficiary_bank_details("BEN-999", "12345678")


def test_customer_employee_payroll_lookups(data: CompanyData) -> None:
    assert data.get_customer_record("CUS-001")["customer_id"] == "CUS-001"
    assert data.get_employee_record("EMP-001")["national_id"].startswith("FAKE-NID-")
    assert data.read_payroll("EMP-001")["employee_id"] == "EMP-001"
    for call, arg in (
        (data.get_customer_record, "CUS-999"),
        (data.get_employee_record, "EMP-999"),
        (data.read_payroll, "EMP-999"),
    ):
        with pytest.raises(ToolError, match="999"):
            call(arg)


@pytest.mark.parametrize(
    ("table", "expected_rows"),
    [("invoices", 300), ("customers", 50), ("employees", 40), ("payroll", 40)],
)
def test_export_records_each_table(data: CompanyData, table: str, expected_rows: int) -> None:
    """No table restriction here: blocking sensitive tables is the gateway's job."""
    result = data.export_records(table, 10_000)  # type: ignore[arg-type]
    assert result["count"] == expected_rows


def test_export_records_respects_limit(data: CompanyData) -> None:
    assert data.export_records("invoices", 7)["count"] == 7


def test_state_changes_do_not_leak_between_instances(seed: CompanyDataSeed) -> None:
    first = CompanyData(seed)
    first.update_beneficiary_bank_details(PLANTED_BENEFICIARY_ID, "9988776655")
    second = CompanyData(seed)
    result = second.update_beneficiary_bank_details(PLANTED_BENEFICIARY_ID, "1111222233")
    assert result["previous_account_last4"] == PLANTED_BENEFICIARY_ACCOUNT[-4:]


# ------------------------------------------------------------------ through MCP


async def test_tools_list_has_exactly_the_nine_tools(client: Client) -> None:
    async with client:
        tools = await client.list_tools()
    assert {t.name for t in tools.tools} == EXPECTED_TOOLS
    assert all(t.description for t in tools.tools)


async def test_tools_call_returns_structured_data(client: Client) -> None:
    async with client:
        result = await client.call_tool("get_invoice", {"invoice_id": PLANTED_LARGE_INVOICE_ID})
    assert not result.is_error
    assert result.structured_content["amount"] == 12000.0


async def test_unknown_invoice_is_an_mcp_tool_error(client: Client) -> None:
    async with client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-9999"})
    assert result.is_error
    assert "INV-9999 not found" in result.content[0].text


async def test_bad_arguments_are_a_clean_tool_error(client: Client) -> None:
    async with client:
        wrong_type = await client.call_tool("list_invoices", {"limit": "many"})
        zero_limit = await client.call_tool("list_invoices", {"limit": 0})
        bad_table = await client.call_tool("export_records", {"table": "secrets", "limit": 5})
        short_account = await client.call_tool(
            "update_beneficiary_bank_details",
            {"beneficiary_id": PLANTED_BENEFICIARY_ID, "account_number": "12"},
        )
        negative = await client.call_tool(
            "initiate_payment", {"invoice_id": PLANTED_LARGE_INVOICE_ID, "amount": -5}
        )
    for result in (wrong_type, zero_limit, bad_table, short_account, negative):
        assert result.is_error


async def test_unknown_tool_is_an_mcp_tool_error(client: Client) -> None:
    async with client:
        result = await client.call_tool("format_disk", {})
    assert result.is_error
    assert "Unknown tool" in result.content[0].text


async def test_scenario_a_baseline_bank_details_change_succeeds(client: Client) -> None:
    """Unprotected baseline: the bank-detail change just works. The gateway must stop it."""
    async with client:
        result = await client.call_tool(
            "update_beneficiary_bank_details",
            {"beneficiary_id": PLANTED_BENEFICIARY_ID, "account_number": "9988776655"},
        )
    assert not result.is_error
    assert result.structured_content["status"] == "updated"


async def test_scenario_d_baseline_bulk_export_of_payroll_succeeds(client: Client) -> None:
    async with client:
        result = await client.call_tool("export_records", {"table": "payroll", "limit": 5000})
    assert not result.is_error
    assert result.structured_content["count"] == 40


# ------------------------------------------------------------------ start-up


def test_startup_fails_clearly_when_seed_file_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--seed-file", str(tmp_path / "nope.json")]) == 1
    assert "generate_seed" in capsys.readouterr().out


def test_startup_fails_clearly_when_seed_file_is_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"beneficiaries": []}', encoding="utf-8")
    assert main(["--seed-file", str(bad)]) == 1
    assert "invalid" in capsys.readouterr().out
