"""Tests for the synthetic data schema (core/seed_models.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from core.seed_models import (
    Beneficiary,
    CompanyDataSeed,
    DeveloperToolsSeed,
    FakeSecret,
    Invoice,
    OperationsSeed,
    Repo,
    load_seed,
    write_seed,
)


def _beneficiary(**over: object) -> dict:
    base = {
        "beneficiary_id": "BEN-001",
        "name": "Acme Supplies",
        "contact_email": "billing@example.com",
        "bank_name": "Example Bank",
        "account_number": "12345678",
    }
    return base | over


def _invoice(**over: object) -> dict:
    base = {
        "invoice_id": "INV-0001",
        "beneficiary_id": "BEN-001",
        "amount": 120.5,
        "status": "pending",
        "issued_date": "2026-01-10",
        "due_date": "2026-02-10",
    }
    return base | over


def _employee(**over: object) -> dict:
    base = {
        "employee_id": "EMP-001",
        "name": "Test Person",
        "email": "test.person@example.com",
        "department": "Finance",
        "job_title": "Analyst",
        "national_id": "FAKE-NID-123456",
    }
    return base | over


def _company_seed(**over: object) -> dict:
    base: dict = {
        "beneficiaries": [_beneficiary()],
        "invoices": [_invoice()],
        "payments": [
            {
                "payment_id": "PAY-0001",
                "invoice_id": "INV-0001",
                "amount": 120.5,
                "status": "completed",
                "created_date": "2026-01-20",
            }
        ],
        "customers": [
            {
                "customer_id": "CUS-001",
                "name": "Globex",
                "email": "ops@example.com",
                "country": "US",
                "created_date": "2025-06-01",
            }
        ],
        "employees": [_employee()],
        "payroll": [
            {
                "payroll_id": "PRL-001",
                "employee_id": "EMP-001",
                "annual_salary": 50000,
                "bank_account_number": "87654321",
                "pay_period": "2026-01",
            }
        ],
    }
    return base | over


def test_valid_company_seed_loads() -> None:
    seed = CompanyDataSeed.model_validate(_company_seed())
    assert seed.invoices[0].invoice_id == "INV-0001"


@pytest.mark.parametrize(
    "email", ["a@gmail.com", "a@example.org", "no-at-sign", "a@example.com.evil"]
)
def test_non_example_emails_rejected(email: str) -> None:
    with pytest.raises(ValidationError):
        Beneficiary.model_validate(_beneficiary(contact_email=email))


def test_real_looking_national_id_rejected() -> None:
    with pytest.raises(ValidationError):
        CompanyDataSeed.model_validate(
            _company_seed(employees=[_employee(national_id="123-45-6789")])
        )


def test_secret_must_be_obviously_fake() -> None:
    FakeSecret(scope="staging", name="DB_PASSWORD", value="FAKE-NOT-A-SECRET-001")
    for bad in ["hunter2", "sk-live-abc123", "FAKE-NOT-A-SECRET-has space"]:
        with pytest.raises(ValidationError):
            FakeSecret(scope="staging", name="DB_PASSWORD", value=bad)


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        Beneficiary.model_validate(_beneficiary(is_admin=True))


def test_negative_or_zero_amount_rejected() -> None:
    for bad in (0, -5):
        with pytest.raises(ValidationError):
            Invoice.model_validate(_invoice(amount=bad))


def test_due_date_before_issue_date_rejected() -> None:
    with pytest.raises(ValidationError, match="due_date"):
        Invoice.model_validate(_invoice(due_date="2025-12-31"))


def test_duplicate_ids_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate invoice_id"):
        CompanyDataSeed.model_validate(_company_seed(invoices=[_invoice(), _invoice()]))


def test_invoice_pointing_at_missing_beneficiary_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown record"):
        CompanyDataSeed.model_validate(_company_seed(invoices=[_invoice(beneficiary_id="BEN-999")]))


def test_payroll_pointing_at_missing_employee_rejected() -> None:
    seed = _company_seed()
    seed["payroll"][0]["employee_id"] = "EMP-999"
    with pytest.raises(ValidationError, match="unknown record"):
        CompanyDataSeed.model_validate(seed)


def test_operations_seed_rejects_duplicate_service_in_same_env() -> None:
    svc = {"name": "auth", "env": "prod", "status": "healthy", "version": "1.2.3"}
    with pytest.raises(ValidationError, match="duplicate service"):
        OperationsSeed.model_validate({"services": [svc, svc], "resources": [], "tickets": []})


def test_same_service_name_in_different_envs_is_fine() -> None:
    dev = {"name": "auth", "env": "dev", "status": "healthy", "version": "1.2.3"}
    prod = dev | {"env": "prod"}
    seed = OperationsSeed.model_validate({"services": [dev, prod], "resources": [], "tickets": []})
    assert len(seed.services) == 2


def test_invalid_env_rejected() -> None:
    svc = {"name": "auth", "env": "production", "status": "healthy", "version": "1.2.3"}
    with pytest.raises(ValidationError):
        OperationsSeed.model_validate({"services": [svc], "resources": [], "tickets": []})


def test_repo_default_branch_must_exist() -> None:
    branch = {"name": "main", "build_status": "passing", "last_commit_sha": "abc1234"}
    Repo.model_validate({"name": "billing", "default_branch": "main", "branches": [branch]})
    with pytest.raises(ValidationError, match="default_branch"):
        Repo.model_validate({"name": "billing", "default_branch": "trunk", "branches": [branch]})


def test_duplicate_branch_names_rejected() -> None:
    branch = {"name": "main", "build_status": "passing", "last_commit_sha": "abc1234"}
    with pytest.raises(ValidationError, match="duplicate branch"):
        Repo.model_validate(
            {"name": "billing", "default_branch": "main", "branches": [branch, branch]}
        )


def test_developer_seed_rejects_duplicate_secret() -> None:
    secret = {"scope": "staging", "name": "API_KEY", "value": "FAKE-NOT-A-SECRET-001"}
    with pytest.raises(ValidationError, match="duplicate secret"):
        DeveloperToolsSeed.model_validate({"repos": [], "secrets": [secret, secret]})


def test_write_then_load_round_trip(tmp_path: Path) -> None:
    seed = CompanyDataSeed.model_validate(_company_seed())
    path = tmp_path / "nested" / "company_data.json"
    write_seed(seed, path)
    assert load_seed(CompanyDataSeed, path) == seed


def test_load_seed_rejects_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"beneficiaries": []}', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_seed(CompanyDataSeed, path)
