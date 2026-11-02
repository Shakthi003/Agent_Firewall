"""Generate the synthetic seed data (Stage 1).

    uv run python -m scripts.generate_seed                   # write data/seed/ (no overwrite)
    uv run python -m scripts.generate_seed --reset           # overwrite existing files
    uv run python -m scripts.generate_seed --seed 7 --reset  # different (but valid) data

The same seed always gives identical files. Every file is re-read through the schema after
writing, so a bad file cannot be left behind silently.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.seed_generator import DEFAULT_SEED, SeedExistsError, write_all
from core.seed_models import CompanyDataSeed, DeveloperToolsSeed, OperationsSeed, load_seed

DEFAULT_OUT = Path("data/seed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic seed data.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (default 42)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--reset", action="store_true", help="overwrite existing files")
    args = parser.parse_args(argv)

    try:
        paths = write_all(args.out, args.seed, reset=args.reset)
    except SeedExistsError as exc:
        print(f"refused: {exc}")
        return 1

    company = load_seed(CompanyDataSeed, paths["company_data"])
    operations = load_seed(OperationsSeed, paths["operations"])
    developer = load_seed(DeveloperToolsSeed, paths["developer_tools"])
    print(f"seed={args.seed} -> {args.out}")
    print(
        f"  company_data: {len(company.beneficiaries)} beneficiaries, "
        f"{len(company.invoices)} invoices, {len(company.payments)} payments, "
        f"{len(company.customers)} customers, {len(company.employees)} employees, "
        f"{len(company.payroll)} payroll"
    )
    print(
        f"  operations: {len(operations.services)} services, "
        f"{len(operations.resources)} resources, {len(operations.tickets)} tickets"
    )
    print(f"  developer_tools: {len(developer.repos)} repos, {len(developer.secrets)} fake secrets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
