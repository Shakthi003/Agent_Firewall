"""Finance Agent (Stage 1): a narrow accounts-payable assistant.

Its tool list comes from `docs/permission-matrix.md`: the seven Company Data tools a finance
role may see. `read_payroll` and `get_employee_record` are not on it.
"""

from __future__ import annotations

from mcp.client import Client

from agents.business.runtime import DEFAULT_MAX_STEPS, AgentRun, run_agent
from core.llm import ChatModel

FINANCE_TOOLS = (
    "get_invoice",
    "list_invoices",
    "get_payment_status",
    "initiate_payment",
    "update_beneficiary_bank_details",
    "get_customer_record",
    "export_records",
)

FINANCE_SYSTEM_PROMPT = """\
You are the Finance Agent for a company's accounts-payable team.

Your job: look up invoices and their payment status, pay approved invoices, keep vendor bank \
details up to date when asked, look up customer records, and export finance records for reports.

Rules:
- Use only the tools you are given. Never invent invoice, vendor or customer ids; look them up.
- Do what the task asks, then reply with a short summary of what you did and found.
- If a tool returns an error, say so plainly. Do not retry the same failing call.
- You work with fake demo data. Amounts are in USD.
"""


async def run_finance_agent(
    *, model: ChatModel, client: Client, task: str, max_steps: int = DEFAULT_MAX_STEPS
) -> AgentRun:
    return await run_agent(
        model=model,
        system_prompt=FINANCE_SYSTEM_PROMPT,
        client=client,
        allowed_tools=FINANCE_TOOLS,
        task=task,
        max_steps=max_steps,
    )
