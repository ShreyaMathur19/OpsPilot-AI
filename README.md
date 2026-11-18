# OpsPilot AI — Autonomous Knowledge Execution Agent

A complete demonstration project for **Assessment Option 3: Autonomous Knowledge Execution Agent**. The LLM autonomously selects tools, reads internal knowledge, reasons about evidence, creates simulated IT incident records, requests human approval for high-impact operations, verifies state changes, and produces an auditable report.

## What is included

- **Internal knowledge:** SQLite devices/alerts/incidents, CSV employee directory, Markdown security policy, JSON response playbooks.
- **LLM-driven tool selection:** OpenAI-compatible `chat/completions` with function calling. No hardcoded decision tree or canned conclusions.
- **Independent execution:** 10 read/action tools; agent can chain tool calls and verify outcomes.
- **Human approval:** `quarantine_device` is blocked until an operator approves it. Denials are recorded and the agent can continue.
- **Memory:** Every run, tool invocation, approval and side effect is persisted to SQLite and remains available after restarting.
- **Audit and export:** Download Markdown reports with tool results and approval logs.
- **Interfaces:** Streamlit dashboard plus CLI; 4 offline automated tests.

## Requirements

- Python **3.10+** (3.11 or 3.12 recommended)
- Either **Ollama** with a tool-calling model (e.g. `qwen2.5:7b`) OR an OpenAI-compatible hosted API with a tool-calling model.
- Internet access may be needed to install dependencies/download the model. With Ollama running, the tool-calling request runs locally.

## Ubuntu / Linux setup

```bash
unzip opspilot_ai.zip
cd opspilot_ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Option A — run locally with Ollama** (install Ollama from its official site first):

```bash
ollama pull qwen2.5:7b
ollama serve
```

If Ollama is already running as a service, **do not start a second `ollama serve`**. In another terminal, activate the virtual environment and launch:

```bash
cd opspilot_ai
source .venv/bin/activate
streamlit run app.py
```

Open the local URL shown by Streamlit, usually `http://localhost:8501`.

**Option B — hosted OpenAI-compatible API:**

```bash
export OPENAI_BASE_URL="https://api.openai.com/v1"
export OPENAI_API_KEY="YOUR_API_KEY"
export OPENAI_MODEL="gpt-4.1-mini"
streamlit run app.py
```

Never commit keys to Git. `.env.example` is a configuration reference; the app uses environment variables and does **not** automatically load `.env`.

## Windows (PowerShell)

```powershell
Expand-Archive .\opspilot_ai.zip -DestinationPath .
cd .\opspilot_ai
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install Ollama, then in a terminal run `ollama pull qwen2.5:7b` and ensure Ollama is running. Then:

```powershell
streamlit run app.py
```

Or set `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `OPENAI_MODEL` in PowerShell to use a hosted provider.

## Demo walkthrough (5 minutes)

1. Open **Investigate** and run the prefilled prompt about `DEV-104`.
2. Watch the dynamic tool activity under the result; actual tool sequence depends on the LLM.
3. If the agent requests quarantine, open **Approvals** and select **Approve** or **Deny**.
4. On approval, the agent resumes and can call `verify_device_status` to inspect the actual SQLite change.
5. View persisted **Records & Audit**, then click **Download Markdown report**.
6. Test `DEV-312`, where unauthorized exposure alone does not justify a confident claim of compromise.

**Expected flow (illustrative, not hardcoded):** retrieve device → alerts → policy → check existing tickets → create ticket → optionally notify owner → request quarantine approval → verify current status → summarize evidence. The LLM is free to choose other legitimate sequences; no exact output is guaranteed.

## CLI (no dashboard required)

```bash
python cli.py --objective "Investigate DEV-104 with internal policy and open a ticket if justified"
python cli.py --list-approvals
python cli.py --approve APR-XXXXXXXXXX
# or
python cli.py --deny APR-XXXXXXXXXX
python cli.py --export RUN-XXXXXXXXXX
```

Use the actual IDs displayed by the program. Exports appear in `reports/`.

## Automated tests

```bash
python -m unittest discover -s tests -v
```

These tests run with a fake LLM and do not need Ollama, a hosted API or API keys. They verify retrieval, tool orchestration, the approval safety gate and state verification. A live integration test should be performed with your selected LLM before submission.

## Repository layout

```text
opspilot_ai/
  app.py                         # Streamlit UI
  cli.py                         # Command-line interface
  opspilot/
    agent.py                     # LLM tool loop + pause/resume
    tools.py                     # Tool descriptions and implementations
    store.py                     # SQLite DB and demo seed
    report.py                    # Markdown reporting
  data/
    employees.csv                # Internal employee directory
    security_policy.md           # Internal reference policy
    response_playbooks.json      # Internal response guidance
  tests/test_agent.py            # No-network unit tests
  examples/demo_prompts.md
  requirements.txt
  .env.example
  .gitignore
  README.md
```

## How autonomy works

Each model turn sees a system instruction, user request, previous tool outputs, and descriptions of available tools. The model chooses what to query and what to do. The controller validates tool names/arguments and executes only explicitly available tools. Every tool call is logged. Sensitive actions create an approval record and stop the run; the reviewer makes the decision, the operation occurs if approved, and the model resumes with the observed result. The model is responsible for evidence-grounded interpretation; deterministic code is responsible for permissions and safety.

This is **LLM-selected tool use**, not fixed action routing. No claims are made that the model always chooses optimal actions. Safety checks are intentionally hard-coded so an LLM cannot bypass approval.

## Known constraints

- The demo uses synthetic seeded snapshots, not real telemetry or real endpoint control. Alert timestamps are generated at first DB initialization.
- No concurrency guarantee or fine-grained authentication: run locally; do not expose Streamlit on a public network without adding authentication and authorization.
- Policy search uses bounded lexical matching, not embeddings; it can miss semantic matches. The model should report gaps rather than fabricate policy.
- Multiple tool calls in one model turn are executed sequentially. Independent tool execution is not parallelized.
- Durable runs and approvals are persisted, but concurrent operators and exactly-once distributed execution are out of scope.
- Some local models can fail tool-calling; use a model with reliable OpenAI-compatible function calling. A model may stop early or not request expected actions.
- No arbitrary code execution or external network actions are available through agent tools.

## Troubleshooting

**Connection refused at localhost:11434:** Check that Ollama is installed and running (`ollama list`), or configure a hosted API.

**404 model not found:** Run `ollama pull qwen2.5:7b` or set `OPENAI_MODEL` to a model you have installed.

**No tools called / malformed tool output:** Choose a model supporting OpenAI-style tool calls; check provider compatibility. Inspect the tool audit.

**No changes visible:** Quarantine is pending approval, or the model decided not to change anything. Check Approvals and Audit.

**Reset demo state:** Stop the app and delete `data/opspilot.db`; the next launch reseeds synthetic devices. This destroys previous runs.

## Reviewer checklist

- [x] Accept natural-language questions about internal knowledge
- [x] Use multiple internal knowledge sources
- [x] Make LLM-driven decisions and execute actions
- [x] Provide explanations grounded in available evidence
- [x] Persist conversation/memory and audit all action calls
- [x] Require human approval before sensitive actions
- [x] Report incomplete information honestly
- [x] Provide README, installation instructions, source and tests
- [ ] Live test with your chosen model and record a demo before submitting

## Attribution

Original demonstration implementation prepared for the assessment. Uses third-party libraries (`requests`, `streamlit`) under their respective licenses. Adapt and understand the source before submitting it as your own work; describe any AI assistance honestly if asked.
