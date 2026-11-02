"""Synthetic data schema (Stage 1).

One seed container per mock MCP server. The generator writes these to `data/seed/`,
and each server loads its own file into memory at startup.

Safety rules are part of the schema, so hand-edited data cannot break them:
- every email must end in `@example.com`
- every secret value must start with `FAKE-NOT-A-SECRET-`
- ids are unique, and references between records must point at records that exist
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

Env = Literal["dev", "staging", "prod"]
InvoiceStatus = Literal["pending", "approved", "paid", "disputed"]
PaymentStatus = Literal["initiated", "completed", "failed"]
ServiceStatus = Literal["healthy", "degraded", "down"]
TicketStatus = Literal["open", "in_progress", "resolved", "closed"]
BuildStatus = Literal["passing", "failing", "unknown"]
ResourceKind = Literal["database", "bucket", "virtual_machine", "queue"]

# `\d{3,}` so a user can supply more records than the default volumes.
_EMAIL = r"^[^@\s]+@example\.com$"
_ACCOUNT = r"^\d{8,12}$"


class _Record(BaseModel):
    """Base for all records: unknown fields are rejected, not ignored."""

    model_config = ConfigDict(extra="forbid")


def _check_unique(label: str, values: Iterable[object]) -> None:
    seen: set[object] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {label}: {value!r}")
        seen.add(value)


def _check_refs(label: str, refs: Iterable[str], known: set[str]) -> None:
    for ref in refs:
        if ref not in known:
            raise ValueError(f"{label} points at unknown record: {ref!r}")


# --------------------------------------------------------------------- Company Data


class Beneficiary(_Record):
    """A payee (vendor). Its bank account is what Scenario A tries to change."""

    beneficiary_id: str = Field(pattern=r"^BEN-\d{3,}$")
    name: str = Field(min_length=1)
    contact_email: str = Field(pattern=_EMAIL)
    bank_name: str = Field(min_length=1)
    account_number: str = Field(pattern=_ACCOUNT)


class Invoice(_Record):
    invoice_id: str = Field(pattern=r"^INV-\d{4,}$")
    beneficiary_id: str = Field(pattern=r"^BEN-\d{3,}$")
    amount: float = Field(gt=0)
    currency: Literal["USD"] = "USD"
    status: InvoiceStatus
    issued_date: date
    due_date: date
    description: str = ""

    @model_validator(mode="after")
    def _due_not_before_issued(self) -> Invoice:
        if self.due_date < self.issued_date:
            raise ValueError(f"{self.invoice_id}: due_date is before issued_date")
        return self


class Payment(_Record):
    payment_id: str = Field(pattern=r"^PAY-\d{4,}$")
    invoice_id: str = Field(pattern=r"^INV-\d{4,}$")
    amount: float = Field(gt=0)
    status: PaymentStatus
    created_date: date


class Customer(_Record):
    customer_id: str = Field(pattern=r"^CUS-\d{3,}$")
    name: str = Field(min_length=1)
    email: str = Field(pattern=_EMAIL)
    country: str = Field(pattern=r"^[A-Z]{2}$")
    created_date: date


class Employee(_Record):
    """Personal data. Hidden from every agent; exists as a target for access tests."""

    employee_id: str = Field(pattern=r"^EMP-\d{3,}$")
    name: str = Field(min_length=1)
    email: str = Field(pattern=_EMAIL)
    department: str = Field(min_length=1)
    job_title: str = Field(min_length=1)
    national_id: str = Field(pattern=r"^FAKE-NID-\d{6}$")


class PayrollRecord(_Record):
    """Critical data. Hidden from every agent; exists as a target for access tests."""

    payroll_id: str = Field(pattern=r"^PRL-\d{3,}$")
    employee_id: str = Field(pattern=r"^EMP-\d{3,}$")
    annual_salary: float = Field(gt=0)
    bank_account_number: str = Field(pattern=_ACCOUNT)
    pay_period: str = Field(pattern=r"^\d{4}-\d{2}$")


class CompanyDataSeed(_Record):
    beneficiaries: list[Beneficiary]
    invoices: list[Invoice]
    payments: list[Payment]
    customers: list[Customer]
    employees: list[Employee]
    payroll: list[PayrollRecord]

    @model_validator(mode="after")
    def _check_integrity(self) -> CompanyDataSeed:
        _check_unique("beneficiary_id", (b.beneficiary_id for b in self.beneficiaries))
        _check_unique("invoice_id", (i.invoice_id for i in self.invoices))
        _check_unique("payment_id", (p.payment_id for p in self.payments))
        _check_unique("customer_id", (c.customer_id for c in self.customers))
        _check_unique("employee_id", (e.employee_id for e in self.employees))
        _check_unique("payroll_id", (p.payroll_id for p in self.payroll))
        _check_refs(
            "invoice.beneficiary_id",
            (i.beneficiary_id for i in self.invoices),
            {b.beneficiary_id for b in self.beneficiaries},
        )
        _check_refs(
            "payment.invoice_id",
            (p.invoice_id for p in self.payments),
            {i.invoice_id for i in self.invoices},
        )
        _check_refs(
            "payroll.employee_id",
            (p.employee_id for p in self.payroll),
            {e.employee_id for e in self.employees},
        )
        return self


# --------------------------------------------------------------------- Operations


class Service(_Record):
    """A service in one environment. `name` + `env` is the key."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    env: Env
    status: ServiceStatus
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")


class Resource(_Record):
    """A deletable infrastructure resource (target of `delete_resource`)."""

    resource_id: str = Field(pattern=r"^RES-\d{3,}$")
    name: str = Field(min_length=1)
    kind: ResourceKind
    env: Env


class Ticket(_Record):
    ticket_id: str = Field(pattern=r"^TCK-\d{3,}$")
    title: str = Field(min_length=1)
    status: TicketStatus
    assignee: str = Field(min_length=1)
    comments: list[str] = Field(default_factory=list)


class OperationsSeed(_Record):
    services: list[Service]
    resources: list[Resource]
    tickets: list[Ticket]

    @model_validator(mode="after")
    def _check_integrity(self) -> OperationsSeed:
        _check_unique("service (name, env)", ((s.name, s.env) for s in self.services))
        _check_unique("resource_id", (r.resource_id for r in self.resources))
        _check_unique("ticket_id", (t.ticket_id for t in self.tickets))
        return self


# --------------------------------------------------------------------- Developer Tools


class Branch(_Record):
    name: str = Field(min_length=1)
    build_status: BuildStatus
    last_commit_sha: str = Field(pattern=r"^[0-9a-f]{7}$")


class Repo(_Record):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    description: str = ""
    default_branch: str
    branches: list[Branch] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_branches(self) -> Repo:
        names = [b.name for b in self.branches]
        _check_unique(f"branch in {self.name}", names)
        if self.default_branch not in names:
            raise ValueError(f"{self.name}: default_branch {self.default_branch!r} does not exist")
        return self


class FakeSecret(_Record):
    """An obviously fake secret returned by `read_env_secrets`. Never a real value."""

    scope: str = Field(min_length=1)
    name: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")
    value: str = Field(pattern=r"^FAKE-NOT-A-SECRET-[A-Z0-9-]+$")


class DeveloperToolsSeed(_Record):
    repos: list[Repo]
    secrets: list[FakeSecret]

    @model_validator(mode="after")
    def _check_integrity(self) -> DeveloperToolsSeed:
        _check_unique("repo name", (r.name for r in self.repos))
        _check_unique("secret (scope, name)", ((s.scope, s.name) for s in self.secrets))
        return self


# --------------------------------------------------------------------- Load / write

SeedT = TypeVar("SeedT", CompanyDataSeed, OperationsSeed, DeveloperToolsSeed)


def load_seed(model: type[SeedT], path: Path) -> SeedT:
    """Read and validate a seed file. Raises `pydantic.ValidationError` if it is invalid."""
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def write_seed(seed: BaseModel, path: Path) -> None:
    """Write a seed file as stable, human-readable JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(seed.model_dump_json(indent=2) + "\n", encoding="utf-8")
