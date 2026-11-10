# Demo script: the dashboard (AC-47)

For the person doing the walkthrough. No code reading is needed. Aim for about 10 minutes.
Success means you can answer the three questions in step 4 **using only the screen**.

## Start

1. In the project folder, run: `uv run python -m scripts.demo_dashboard`
2. Wait for the line `Demo dashboard: http://127.0.0.1:8000`.
3. Open that address. Sign in as `approver` with password `demo-approver`.

The data is fake and temporary. Nothing you do here touches a real database.

## 1. Overview (1 minute)

- At the top, is the banner green and does it say **Audit chain intact**?
- Find: how many agent calls were checked, how many were blocked, how many are waiting for a human.
- Which reason stopped the most calls?

## 2. Audit log (2 minutes)

1. Open **Audit log**. Click the **Blocked** filter.
2. Click any row. A panel opens on the right.
3. Read the box that starts "What this means". Does it make sense without any other help?
4. Find the policy version and the two hash values under "Tamper-evident chain".
5. Type `payroll` in the search box. Do the results change?

## 3. Approvals (2 minutes)

1. Open **Approvals**. There should be three requests waiting.
2. Look at one card. Can you tell who asked, for what, with which exact values, and how long is left?
3. Click **Reject**, then **Yes, reject**. The card should move to History as **Rejected**.
4. Click **Approve** on another one, then **Yes, approve**. It should move to History as **Approved**.

## 4. Attack lab (4 minutes) - the main test

1. Open **Attack lab**. Pick **A** (the invoice that tells the agent to change a bank account).
2. Read the box "Hidden in the data it reads". This is the attack.
3. Press **Run attack**. Wait a second or two.
4. Answer, using only what is on screen:
   - **What did the gateway decide for each unsafe call, and why?** (section 1)
   - **What is the evidence?** Click one `evidence #` button and read the panel. (section 2)
   - **What does the investigation conclude, and how severe is it?** Click a blue `#n` number in the report. (section 3)
5. Run scenario **B** and **C** too. Is it clear which calls were blocked and which were only paused?

## Tell us

- Where did you get stuck or have to guess?
- Was any word unclear? (For example "enforcement", "hash chain", "policy version".)
- Did anything look broken or wrong?
- Could you do step 4 without help? Yes or no.

Write the answers down. If step 4 needed help, AC-47 is not met yet.

## Stop

Press `Ctrl+C` in the terminal.

---

# Recruiter demo (about 5 minutes, for the recording)

A script for the person presenting. It tells one story: the same agents, first unprotected, then behind the gateway. Run `uv run python -m scripts.demo_dashboard` first and sign in as above. Say the data is synthetic and every tool is a mock.

| Minute | Show | Say |
| -- | -- | -- |
| 0:00 | README architecture diagram | "AI agents call company tools. Every call goes through one gateway that checks who is asking, applies written rules, and records everything. Agents have no other route to the tools." |
| 0:30 | `uv run python -m scripts.run_baseline replay` (prints "UNPROTECTED BASELINE") | "Without the gateway, all 12 planned unsafe calls succeed: a bank-detail change, a production delete, a secrets read, a bulk export." |
| 1:00 | Dashboard **Overview** | "Behind the gateway, normal work is allowed and the unsafe calls are stopped. The green banner says the audit log has not been altered." |
| 1:30 | **Attack lab**, scenario **B**, **Run attack** | "The ticket text tells the agent to delete the production database. The agent may be fooled. The gateway still blocks the call before it reaches the server, with reason `PROD_DESTRUCTIVE_DENIED`." |
| 2:15 | Click an `evidence #` button in the result | "Every decision is an audit record: who, which tool, which rule, which policy version, and a hash linking it to the previous record." |
| 2:45 | **Attack lab**, scenario **A**; then **Approvals**; press **Approve** | "A bank-detail change is not blocked, it is paused. A human sees the exact values and approves. The approval works once, for exactly that request." |
| 3:30 | Back in the lab result, the investigation section; click a blue `#n` | "An advisory workflow reads only the audit log and explains what happened. Each claim cites event numbers, and it cannot change a decision." |
| 4:15 | **Policies** page, then `docs/evaluation-report.md` | "The rules are readable and versioned. In the evaluation, 12 of 12 unsafe calls ran unprotected and 0 of 12 ran through the gateway. These are simulated results on attacks I wrote, not a claim about real-world accuracy." |
| 4:45 | README "Limitations" | "What it does not do: it cannot protect a route that skips the gateway, and it does not stop prompt injection itself, only the resulting call." |

Before recording: sign out and back in once so the login is not on screen, and keep the terminal font large.

