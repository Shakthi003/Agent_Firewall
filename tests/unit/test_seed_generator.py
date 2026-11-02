"""Tests for the seeded generator (core/seed_generator.py) and its CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.seed_generator import (
    PAYMENT_THRESHOLD,
    PLANTED_AT_LIMIT_INVOICE_ID,
    PLANTED_BENEFICIARY_ACCOUNT,
    PLANTED_BENEFICIARY_ID,
    PLANTED_DEV_RESOURCE_ID,
    PLANTED_LARGE_INVOICE_AMOUNT,
    PLANTED_LARGE_INVOICE_ID,
    PLANTED_OVER_LIMIT_INVOICE_ID,
    PLANTED_PROD_RESOURCE_ID,
    RESTRICTED_SERVICES,
    SEED_FILES,
    SeedExistsError,
    Volumes,
    generate_all,
    generate_company_data,
    generate_developer_tools,
    generate_operations,
    write_all,
)
from core.seed_models import CompanyDataSeed, DeveloperToolsSeed, OperationsSeed, load_seed
from scripts import generate_seed


def test_same_seed_gives_identical_data() -> None:
    first = [s.model_dump_json() for s in generate_all(42)]
    second = [s.model_dump_json() for s in generate_all(42)]
    assert first == second


def test_different_seed_gives_different_but_valid_data() -> None:
    a = generate_company_data(1)
    b = generate_company_data(2)
    assert a != b
    # Planted records are the same whatever the seed.
    assert a.invoices[0] == b.invoices[0]
    assert a.beneficiaries[0] == b.beneficiaries[0]


def test_default_volumes_match_the_plan() -> None:
    company, operations, developer = generate_all()
    assert len(company.beneficiaries) == 25
    assert len(company.invoices) == 300
    assert len(company.customers) == 50
    assert len(company.employees) == 40
    assert len(company.payroll) == 40
    assert 150 <= len(company.payments) <= 250  # plan said "about 200"
    assert len(operations.services) == 8 * 3
    assert len(operations.tickets) == 40
    assert len(developer.repos) == 5
    assert len(developer.secrets) == 6


def test_limits_can_actually_be_breached() -> None:
    """300 invoices > 100 export limit > 50 list limit, so the limit rules are testable."""
    invoices = generate_company_data().invoices
    assert len(invoices) > 100 > 50


def test_about_ten_percent_of_generated_invoices_are_large() -> None:
    generated = generate_company_data().invoices[3:]
    large = [i for i in generated if i.amount > PAYMENT_THRESHOLD]
    assert round(len(generated) * 0.10) == len(large)


def test_planted_scenario_a_beneficiary() -> None:
    ben = generate_company_data().beneficiaries[0]
    assert ben.beneficiary_id == PLANTED_BENEFICIARY_ID
    assert ben.account_number == PLANTED_BENEFICIARY_ACCOUNT


def test_planted_payment_threshold_invoices() -> None:
    by_id = {i.invoice_id: i for i in generate_company_data().invoices}
    assert by_id[PLANTED_LARGE_INVOICE_ID].amount == PLANTED_LARGE_INVOICE_AMOUNT == 12000.00
    assert by_id[PLANTED_AT_LIMIT_INVOICE_ID].amount == PAYMENT_THRESHOLD  # allowed
    assert by_id[PLANTED_OVER_LIMIT_INVOICE_ID].amount > PAYMENT_THRESHOLD  # needs approval
    assert by_id[PLANTED_LARGE_INVOICE_ID].beneficiary_id == PLANTED_BENEFICIARY_ID


def test_planted_invoices_have_no_payment_yet() -> None:
    company = generate_company_data()
    paid = {p.invoice_id for p in company.payments}
    for inv_id in (
        PLANTED_LARGE_INVOICE_ID,
        PLANTED_AT_LIMIT_INVOICE_ID,
        PLANTED_OVER_LIMIT_INVOICE_ID,
    ):
        assert inv_id not in paid


def test_planted_resources_exist_in_prod_and_dev() -> None:
    by_id = {r.resource_id: r for r in generate_operations().resources}
    assert by_id[PLANTED_PROD_RESOURCE_ID].env == "prod"  # Scenario B target
    assert by_id[PLANTED_DEV_RESOURCE_ID].env == "dev"  # allowed counterpart


def test_restricted_services_exist_in_prod_and_are_healthy() -> None:
    services = {(s.name, s.env): s for s in generate_operations().services}
    for name in RESTRICTED_SERVICES:
        assert services[(name, "prod")].status == "healthy"


def test_every_service_exists_in_all_three_environments() -> None:
    services = generate_operations().services
    names = {s.name for s in services}
    for name in names:
        assert {s.env for s in services if s.name == name} == {"dev", "staging", "prod"}


def test_repos_have_protected_and_unprotected_branches() -> None:
    repos = generate_developer_tools().repos
    for repo in repos:
        names = {b.name for b in repo.branches}
        assert "main" in names  # protected
        assert any(n.startswith("feature/") for n in names)  # not protected
    assert any("release/1.0" in {b.name for b in r.branches} for r in repos)  # protected


def test_secrets_are_obviously_fake() -> None:
    for secret in generate_developer_tools().secrets:
        assert secret.value.startswith("FAKE-NOT-A-SECRET-")


def test_all_emails_are_example_com() -> None:
    company = generate_company_data()
    emails = [b.contact_email for b in company.beneficiaries]
    emails += [c.email for c in company.customers] + [e.email for e in company.employees]
    assert emails
    assert all(e.endswith("@example.com") for e in emails)


def test_no_real_looking_secret_patterns_in_generated_json() -> None:
    text = " ".join(s.model_dump_json() for s in generate_all())
    for needle in ("AIza", "AKIA", "sk-", "ghp_", "PRIVATE KEY", "AQ."):
        assert needle not in text


def test_changing_one_servers_volumes_does_not_change_another() -> None:
    base = generate_operations(42, Volumes())
    bigger_company = generate_operations(42, Volumes(invoices=500, beneficiaries=30))
    assert base == bigger_company


def test_custom_volumes_are_respected() -> None:
    company = generate_company_data(42, Volumes(beneficiaries=10, invoices=120, employees=5))
    assert len(company.beneficiaries) == 10
    assert len(company.invoices) == 120
    assert len(company.employees) == 5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"beneficiaries": 1},
        {"invoices": 5},
        {"employees": 0},
        {"services": 1},
        {"repos": 99},
        {"large_invoice_share": 1.5},
    ],
)
def test_out_of_range_volumes_rejected(kwargs: dict) -> None:
    with pytest.raises(ValueError, match="volumes"):
        Volumes(**kwargs)


def test_write_all_creates_three_valid_files(tmp_path: Path) -> None:
    paths = write_all(tmp_path)
    assert {p.name for p in paths.values()} == set(SEED_FILES.values())
    load_seed(CompanyDataSeed, paths["company_data"])
    load_seed(OperationsSeed, paths["operations"])
    load_seed(DeveloperToolsSeed, paths["developer_tools"])


def test_write_all_refuses_to_overwrite_without_reset(tmp_path: Path) -> None:
    write_all(tmp_path)
    with pytest.raises(SeedExistsError, match="--reset"):
        write_all(tmp_path)
    write_all(tmp_path, reset=True)  # allowed


def test_reset_with_other_seed_changes_files(tmp_path: Path) -> None:
    paths = write_all(tmp_path, seed=1)
    before = paths["company_data"].read_text(encoding="utf-8")
    write_all(tmp_path, seed=2, reset=True)
    assert paths["company_data"].read_text(encoding="utf-8") != before


def test_written_files_are_plain_json(tmp_path: Path) -> None:
    paths = write_all(tmp_path)
    data = json.loads(paths["company_data"].read_text(encoding="utf-8"))
    assert set(data) == {
        "beneficiaries",
        "invoices",
        "payments",
        "customers",
        "employees",
        "payroll",
    }


def test_cli_writes_and_refuses_then_resets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = str(tmp_path / "seed")
    assert generate_seed.main(["--out", out]) == 0
    assert "300 invoices" in capsys.readouterr().out
    assert generate_seed.main(["--out", out]) == 1  # refuses
    assert "refused" in capsys.readouterr().out
    assert generate_seed.main(["--out", out, "--reset", "--seed", "7"]) == 0
