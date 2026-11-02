# Agent Firewall

Enterprise AI agent security and governance platform: a policy-enforcing MCP gateway that sits between AI agents and the tools they use.

> Status: early development (Stage 0). This README is a placeholder and will be completed in Stage 9.

## Design documents

- [Permission matrix](docs/permission-matrix.md)
- [Threat model](docs/threat-model.md)
- [Architecture and request flows](docs/architecture.md)
- [Acceptance criteria](docs/acceptance-criteria.md)

## Setup (work in progress)

```powershell
uv sync
copy .env.example .env   # then fill in real values
```

## Synthetic data

All data in this project is synthetic and all operations are mocks. The data lives in `data/seed/` as three JSON files, one per mock MCP server (`company_data.json`, `operations.json`, `developer_tools.json`).

```powershell
uv run python -m scripts.generate_seed                   # write data/seed/ (refuses to overwrite)
uv run python -m scripts.generate_seed --reset           # overwrite with the default data (seed 42)
uv run python -m scripts.generate_seed --seed 7 --reset  # different, equally valid data
```

The same seed always produces identical files. A few records are planted at fixed ids whatever the seed, because the attack scenarios depend on them (for example `BEN-001`, the 12,000 USD invoice `INV-0001`, and the `RES-001` production database).

**Bring your own data:** replace the JSON files in `data/seed/`. They are checked against the schema in `core/seed_models.py` when a server starts: emails must end in `@example.com`, secrets must start with `FAKE-NOT-A-SECRET-`, ids must be unique, and references must point at records that exist. Keep equivalent records for the planted scenarios, or those scenarios will not trigger. There is deliberately no upload feature.
