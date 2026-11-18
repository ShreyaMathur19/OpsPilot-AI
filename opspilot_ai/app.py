
"""
OpsPilot AI - Autonomous Operations Center

Features:
- Operations overview dashboard
- LLM-powered autonomous investigations
- Incident management
- Internal knowledge center
- Human approval management
- Agent execution timeline
- Analytics and audit logging
- Live security event ingestion
- Automatic event investigations
- Historical investigation memory
- Agent evaluation laboratory

All device actions are simulated.
"""

import csv
import json
import os
import uuid
from pathlib import Path

import streamlit as st

from opspilot import store
from opspilot.agent import Agent
from opspilot.report import markdown_report
from opspilot.tools import execute_tool
from opspilot import events
from opspilot.memory import similar_cases
from opspilot.evaluator import evaluate


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="OpsPilot AI | Autonomous Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ROOT = Path(__file__).resolve().parent

# Initialize database and event tables.
store.init_db()
events.ensure_tables()


# ============================================================
# STYLING
# ============================================================

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    h1, h2, h3 {
        letter-spacing: -0.5px;
    }

    div[data-testid="stMetric"] {
        background: rgba(128,128,128,0.06);
        border: 1px solid rgba(128,128,128,0.18);
        border-radius: 12px;
        padding: 18px;
    }

    div[data-testid="stMetricLabel"] {
        font-weight: 500;
    }

    div[data-testid="stMetricValue"] {
        font-weight: 700;
    }

    div[data-testid="stExpander"] {
        border-radius: 10px;
    }

    .section-caption {
        opacity: 0.7;
        font-size: 13px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DATABASE HELPERS
# ============================================================

def rows(sql, params=()):
    """Execute a SELECT query."""
    return store.query(sql, params)


def count(table, where="1=1"):
    """
    Return count from known application tables.

    Never pass untrusted user input as a table or
    WHERE clause.
    """
    allowed_tables = {
        "devices",
        "alerts",
        "incidents",
        "approvals",
        "runs",
        "audit",
        "notifications",
        "incoming_events",
    }

    if table not in allowed_tables:
        raise ValueError("Unsupported table")

    result = rows(
        f"SELECT COUNT(*) AS total FROM {table} "
        f"WHERE {where}"
    )

    return result[0]["total"] if result else 0


def parse_json(value):
    """Parse stored JSON when possible."""
    if value is None:
        return {}

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return value


def display_json(value):
    """Display JSON or ordinary text safely."""
    parsed = parse_json(value)

    if isinstance(parsed, (dict, list)):
        st.json(parsed)
    else:
        st.code(str(parsed), language=None)


def get_devices():
    return rows("""
        SELECT *
        FROM devices
        ORDER BY device_id
    """)


def get_runs(limit=100):
    return rows("""
        SELECT *
        FROM runs
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))


def get_incidents():
    return rows("""
        SELECT *
        FROM incidents
        ORDER BY created_at DESC
    """)


def get_approvals():
    return rows("""
        SELECT *
        FROM approvals
        ORDER BY created_at DESC
    """)


def get_alerts():
    return rows("""
        SELECT *
        FROM alerts
        ORDER BY observed_at DESC
    """)


# ============================================================
# STATUS HELPERS
# ============================================================

def show_status(status):

    if status == "completed":
        st.success("Investigation completed")

    elif status == "awaiting_approval":
        st.warning("Waiting for human approval")

    elif status == "running":
        st.info("Investigation in progress")

    elif status in ("error", "failed", "step_limit"):
        st.error(f"Investigation status: {status}")

    else:
        st.info(f"Status: {status}")


def show_run_summary(run):

    st.markdown("### Investigation Details")

    st.caption(
        f"Run ID: {run['id']} | "
        f"Created: {run['created_at']} | "
        f"Steps: {run['steps']}"
    )

    show_status(run["status"])

    st.markdown("#### Objective")
    st.write(run["objective"])

    st.markdown("#### Agent Findings")

    result = run["result"]

    if result:
        st.markdown(result)
    else:
        st.info("No final report available yet.")

    try:
        report = markdown_report(run["id"])

        st.download_button(
            "⬇ Download Investigation Report",
            data=report,
            file_name=f"{run['id']}.md",
            mime="text/markdown",
            key=f"report_{run['id']}",
        )

    except Exception as exc:
        st.warning(
            f"Report could not be generated: {exc}"
        )


# ============================================================
# AGENT EXECUTION TIMELINE
# ============================================================

def show_execution_timeline(run_id):

    logs = rows("""
        SELECT *
        FROM audit
        WHERE run_id=?
        ORDER BY id ASC
    """, (run_id,))

    st.markdown("### Agent Execution Timeline")

    if not logs:
        st.info(
            "No tool executions were recorded for this run."
        )
        return

    st.caption(
        f"{len(logs)} recorded tool event(s)"
    )

    for index, log in enumerate(logs, start=1):

        tool_name = log["tool"]

        arguments = parse_json(
            log["arguments"]
        )

        outcome = parse_json(
            log["outcome"]
        )

        is_error = (
            isinstance(outcome, dict)
            and "error" in outcome
        )

        is_approval = (
            isinstance(outcome, dict)
            and outcome.get("approval_required")
        )

        if is_error:
            icon = "❌"
        elif is_approval:
            icon = "⏳"
        else:
            icon = "✅"

        with st.expander(
            f"{icon} Step {index}: {tool_name}"
        ):

            st.caption(
                f"Executed: {log['created_at']}"
            )

            left, right = st.columns(2)

            with left:
                st.markdown("**Tool Arguments**")
                display_json(arguments)

            with right:
                st.markdown("**Tool Result**")
                display_json(outcome)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ OpsPilot AI")

    st.caption(
        "Autonomous IT Operations Platform"
    )

    st.divider()

    st.markdown("### AI Environment")

    model_name = os.getenv(
        "OPENAI_MODEL",
        "qwen2.5:3b"
    )

    st.code(
        model_name,
        language=None
    )

    st.caption(
        "Provider: Ollama / OpenAI-compatible API"
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "📊 Overview",
            "🤖 AI Investigations",
            "🚨 Incident Center",
            "📚 Knowledge Center",
            "🔐 Approvals",
            "🧭 Agent Activity",
            "📋 Analytics & Audit",
            "📡 Live Events",
            "🧠 Agent Memory",
            "🧪 Evaluation Lab",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.caption(
        "Simulation environment"
    )

    st.caption(
        "No real devices are controlled."
    )


# ============================================================
# PAGE 1 - OVERVIEW
# ============================================================

if page == "📊 Overview":

    st.title("Operations Overview")

    st.caption(
        "AI-powered endpoint monitoring and "
        "autonomous security investigations"
    )

    # --------------------------------------------------------
    # TOP METRICS
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Devices",
            count("devices")
        )

    with col2:
        st.metric(
            "Noncompliant",
            count(
                "devices",
                "compliance='noncompliant'"
            )
        )

    with col3:
        st.metric(
            "Open Incidents",
            count(
                "incidents",
                "state='open'"
            )
        )

    with col4:
        st.metric(
            "Pending Approvals",
            count(
                "approvals",
                "status='pending'"
            )
        )

    st.write("")

    col5, col6, col7, col8 = st.columns(4)

    with col5:
        st.metric(
            "Completed Runs",
            count(
                "runs",
                "status='completed'"
            )
        )

    with col6:
        st.metric(
            "Failed Runs",
            count(
                "runs",
                "status='error'"
            )
        )

    with col7:
        st.metric(
            "Quarantined Devices",
            count(
                "devices",
                "status='quarantined'"
            )
        )

    with col8:
        st.metric(
            "Total Alerts",
            count("alerts")
        )

    st.divider()

    # --------------------------------------------------------
    # DEVICE INVENTORY
    # --------------------------------------------------------

    st.subheader("Device Inventory")

    devices = get_devices()

    if devices:
        st.dataframe(
            devices,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No device records available.")

    st.divider()

    # --------------------------------------------------------
    # RECENT INVESTIGATIONS
    # --------------------------------------------------------

    st.subheader("Recent Investigations")

    recent_runs = get_runs(limit=10)

    if recent_runs:

        summary = [
            {
                "Run ID": r["id"],
                "Objective": r["objective"],
                "Status": r["status"],
                "Steps": r["steps"],
                "Created": r["created_at"]
            }
            for r in recent_runs
        ]

        st.dataframe(
            summary,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No investigations available.")


# ============================================================
# PAGE 2 - AI INVESTIGATIONS
# ============================================================

elif page == "🤖 AI Investigations":

    st.title("AI Investigations")

    st.caption(
        "Autonomous reasoning, knowledge retrieval "
        "and controlled action execution"
    )

    examples = {

        "Security Investigation":
            "Investigate DEV-104 using current "
            "device evidence, security alerts, "
            "internal policies and previous incidents. "
            "Take justified actions, request approval "
            "before quarantine, and verify results.",

        "Compliance Analysis":
            "Investigate all noncompliant devices. "
            "Identify security risks and relevant "
            "policy violations. Prioritize remediation "
            "using available evidence.",

        "Incident Review":
            "Review open incidents and identify "
            "which require further investigation. "
            "Use current device evidence and "
            "internal security policies.",

        "Historical Investigation":
            "Investigate DEV-104 and search relevant "
            "previous investigations. Compare historical "
            "findings with current device evidence.",

        "Safe Response":
            "Investigate DEV-312 and determine whether "
            "any remediation action is justified. "
            "Do not quarantine without human approval."
    }

    example = st.selectbox(
        "Choose an example scenario",
        ["Custom"] + list(examples.keys())
    )

    default_objective = (
        examples.get(example)
        if example != "Custom"
        else (
            "Investigate DEV-104 using available "
            "internal evidence and policies. "
            "Explain risks and take justified "
            "simulated actions."
        )
    )

    objective = st.text_area(
        "Investigation Objective",
        value=default_objective,
        height=130
    )

    if st.button(
        "🚀 Run Autonomous Investigation",
        type="primary"
    ):

        if not objective.strip():
            st.warning(
                "Please enter an investigation objective."
            )

        else:

            try:

                with st.spinner(
                    "Agent investigating..."
                ):

                    result = Agent().start(
                        objective
                    )

                st.session_state["selected_run"] = (
                    result["run_id"]
                )

                st.rerun()

            except Exception as exc:
                st.error(
                    f"Investigation failed: {exc}"
                )

    st.divider()

    st.subheader("Investigation History")

    runs = get_runs(limit=100)

    if runs:

        run_ids = [
            r["id"]
            for r in runs
        ]

        saved_run = st.session_state.get(
            "selected_run"
        )

        selected_index = (
            run_ids.index(saved_run)
            if saved_run in run_ids
            else 0
        )

        selected_run = st.selectbox(
            "Select Investigation",
            run_ids,
            index=selected_index,
            format_func=lambda rid: next(
                (
                    f"{r['id']} | {r['status']} | "
                    f"{r['objective'][:65]}"
                    for r in runs
                    if r["id"] == rid
                ),
                rid
            )
        )

        st.session_state[
            "selected_run"
        ] = selected_run

        run = store.get_run(
            selected_run
        )

        if run:

            show_run_summary(run)

            if run["status"] in (
                "error",
                "step_limit",
            ):

                if st.button(
                    "Retry Investigation",
                    key="retry_run"
                ):

                    with st.spinner(
                        "Resuming investigation..."
                    ):

                        Agent().continue_run(
                            selected_run
                        )

                    st.rerun()

            st.divider()

            show_execution_timeline(
                selected_run
            )

    else:
        st.info(
            "Start an investigation to see its results."
        )


# ============================================================
# PAGE 3 - INCIDENT CENTER
# ============================================================

elif page == "🚨 Incident Center":

    st.title("Incident Center")

    st.caption(
        "Security incidents created through "
        "the autonomous agent"
    )

    incidents = get_incidents()

    col1, col2 = st.columns(2)

    col1.metric(
        "Total Incidents",
        count("incidents")
    )

    col2.metric(
        "Open Incidents",
        count(
            "incidents",
            "state='open'"
        )
    )

    st.divider()

    if incidents:

        st.dataframe(
            incidents,
            use_container_width=True,
            hide_index=True
        )

        incident_ids = [
            i["id"]
            for i in incidents
        ]

        selected = st.selectbox(
            "Inspect Incident",
            incident_ids
        )

        incident = next(
            i for i in incidents
            if i["id"] == selected
        )

        st.subheader("Incident Details")

        display_json(incident)

        st.subheader("Associated Device")

        device_id = incident["device_id"]

        try:

            device = execute_tool(
                "get_device",
                {"device_id": device_id}
            )

            display_json(device)

        except Exception as exc:
            st.error(str(exc))

        st.subheader("Associated Alerts")

        try:

            alerts = execute_tool(
                "get_alerts",
                {"device_id": device_id}
            )

            display_json(alerts)

        except Exception as exc:
            st.error(str(exc))

    else:

        st.info(
            "No incidents have been created yet."
        )


# ============================================================
# PAGE 4 - KNOWLEDGE CENTER
# ============================================================

elif page == "📚 Knowledge Center":

    st.title("Internal Knowledge Center")

    st.caption(
        "Internal sources available for autonomous "
        "investigations"
    )

    source = st.selectbox(
        "Knowledge Source",
        [
            "Security Policies",
            "Response Playbooks",
            "Employees",
            "Device Database",
            "Security Alerts",
            "Incident History",
        ]
    )

    if source == "Security Policies":

        path = (
            ROOT / "data" / "security_policy.md"
        )

        if path.exists():

            st.markdown(
                path.read_text(
                    encoding="utf-8"
                )
            )

    elif source == "Response Playbooks":

        path = (
            ROOT / "data" / "response_playbooks.json"
        )

        if path.exists():

            st.json(
                json.loads(
                    path.read_text(
                        encoding="utf-8"
                    )
                )
            )

    elif source == "Employees":

        path = (
            ROOT / "data" / "employees.csv"
        )

        if path.exists():

            with path.open(
                encoding="utf-8",
                newline=""
            ) as f:

                employee_data = list(
                    csv.DictReader(f)
                )

            st.dataframe(
                employee_data,
                use_container_width=True,
                hide_index=True
            )

    elif source == "Device Database":

        st.dataframe(
            get_devices(),
            use_container_width=True,
            hide_index=True
        )

    elif source == "Security Alerts":

        st.dataframe(
            get_alerts(),
            use_container_width=True,
            hide_index=True
        )

    elif source == "Incident History":

        st.dataframe(
            get_incidents(),
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    st.subheader("Knowledge Search")

    query = st.text_input(
        "Search internal policies",
        value="malware quarantine approval"
    )

    if st.button(
        "Search Knowledge"
    ):

        try:

            result = execute_tool(
                "search_knowledge",
                {"query": query}
            )

            display_json(result)

        except Exception as exc:
            st.error(str(exc))


# ============================================================
# PAGE 5 - APPROVALS
# ============================================================

elif page == "🔐 Approvals":

    st.title("Human Approval Center")

    st.caption(
        "Review sensitive actions before simulated execution"
    )

    pending = rows("""
        SELECT *
        FROM approvals
        WHERE status='pending'
        ORDER BY created_at
    """)

    st.metric(
        "Pending Approvals",
        len(pending)
    )

    if not pending:

        st.success(
            "No pending approvals"
        )

    for approval in pending:

        approval_id = approval["id"]

        st.warning(
            f"Approval Required: {approval_id}"
        )

        st.write(
            "**Run:**",
            approval["run_id"]
        )

        st.write(
            "**Action:**",
            approval["tool"]
        )

        st.markdown("**Arguments**")

        display_json(
            approval["arguments"]
        )

        note = st.text_input(
            "Reviewer Note",
            key=f"note_{approval_id}"
        )

        col1, col2 = st.columns(2)

        with col1:

            if st.button(
                "✅ Approve",
                key=f"approve_{approval_id}",
                type="primary"
            ):

                try:

                    with st.spinner(
                        "Executing approved action..."
                    ):

                        result = Agent().review(
                            approval_id,
                            True,
                            note
                        )

                    st.session_state[
                        "selected_run"
                    ] = result["run_id"]

                    st.rerun()

                except Exception as exc:
                    st.error(str(exc))

        with col2:

            if st.button(
                "❌ Reject",
                key=f"reject_{approval_id}"
            ):

                try:

                    with st.spinner(
                        "Recording rejection..."
                    ):

                        result = Agent().review(
                            approval_id,
                            False,
                            note
                        )

                    st.session_state[
                        "selected_run"
                    ] = result["run_id"]

                    st.rerun()

                except Exception as exc:
                    st.error(str(exc))

        st.divider()

    st.subheader("Approval History")

    approvals = get_approvals()

    if approvals:

        st.dataframe(
            approvals,
            hide_index=True,
            use_container_width=True
        )


# ============================================================
# PAGE 6 - AGENT ACTIVITY
# ============================================================

elif page == "🧭 Agent Activity":

    st.title("Agent Activity & Execution Replay")

    st.caption(
        "Review actual tool execution records "
        "from previous investigations"
    )

    runs = get_runs()

    if not runs:

        st.info("No investigation history available.")

    else:

        st.dataframe(
            [
                {
                    "Run ID": r["id"],
                    "Status": r["status"],
                    "Steps": r["steps"],
                    "Created": r["created_at"]
                }
                for r in runs
            ],
            hide_index=True,
            use_container_width=True
        )

        selected = st.selectbox(
            "Replay Investigation",
            [r["id"] for r in runs]
        )

        run = store.get_run(selected)

        if run:

            show_status(
                run["status"]
            )

            st.markdown(
                "### Original Objective"
            )

            st.write(
                run["objective"]
            )

            show_execution_timeline(
                selected
            )

            st.markdown(
                "### Final Agent Report"
            )

            st.markdown(
                run["result"]
                or "No final report available."
            )


# ============================================================
# PAGE 7 - ANALYTICS & AUDIT
# ============================================================

elif page == "📋 Analytics & Audit":

    st.title("Analytics & Audit")

    st.caption(
        "Investigation outcomes, tool activity "
        "and persistent audit history"
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Investigations",
        count("runs")
    )

    col2.metric(
        "Tool Executions",
        count("audit")
    )

    col3.metric(
        "Notifications",
        count("notifications")
    )

    st.divider()

    st.subheader("Investigation Outcomes")

    status_counts = rows("""
        SELECT status, COUNT(*) AS total
        FROM runs
        GROUP BY status
    """)

    if status_counts:

        chart_data = {
            r["status"]: r["total"]
            for r in status_counts
        }

        st.bar_chart(chart_data)

    st.divider()

    st.subheader("Audit History")

    audit = rows("""
        SELECT *
        FROM audit
        ORDER BY id DESC
        LIMIT 300
    """)

    if audit:

        st.dataframe(
            audit,
            hide_index=True,
            use_container_width=True
        )

        st.download_button(
            "⬇ Download Audit JSON",
            data=json.dumps(
                audit,
                indent=2,
                default=str
            ),
            file_name="opspilot_audit.json",
            mime="application/json"
        )

    st.subheader("Notification Outbox")

    notifications = rows("""
        SELECT *
        FROM notifications
        ORDER BY created_at DESC
    """)

    if notifications:

        st.dataframe(
            notifications,
            hide_index=True,
            use_container_width=True
        )


# ============================================================
# PAGE 8 - LIVE EVENTS
# ============================================================

elif page == "📡 Live Events":

    st.title("Live Security Events")

    st.caption(
        "Ingest security events and trigger "
        "autonomous AI investigations"
    )

    event_rows = events.recent()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        len(event_rows)
    )

    col2.metric(
        "Pending Events",
        sum(
            e["state"] == "pending"
            for e in event_rows
        )
    )

    col3.metric(
        "Completed",
        sum(
            e["state"] == "completed"
            for e in event_rows
        )
    )

    col4.metric(
        "Failed",
        sum(
            e["state"] == "failed"
            for e in event_rows
        )
    )

    st.divider()

    st.subheader(
        "Simulate Incoming Security Event"
    )

    device_records = get_devices()

    if not device_records:
        st.warning("No devices available.")
        st.stop()

    device_ids = [
        d["device_id"]
        for d in device_records
    ]

    with st.form("event_form"):

        device_id = st.selectbox(
            "Target Device",
            device_ids
        )

        category = st.selectbox(
            "Event Category",
            [
                "malware",
                "authentication",
                "configuration",
                "patching",
                "network",
                "other"
            ]
        )

        severity = st.selectbox(
            "Severity",
            [
                "low",
                "medium",
                "high",
                "critical"
            ]
        )

        description = st.text_area(
            "Event Description",
            value=(
                "Suspicious activity detected "
                "on monitored endpoint."
            ),
            height=110
        )

        submitted = st.form_submit_button(
            "📡 Ingest Security Event",
            type="primary"
        )

    if submitted:

        payload = {
            "event_id": (
                "EVT-"
                + uuid.uuid4().hex[:10].upper()
            ),
            "device_id": device_id,
            "category": category,
            "severity": severity,
            "description": description
        }

        try:

            result = events.ingest(
                payload
            )

            st.success(
                "Event successfully ingested."
            )

            display_json(result)

        except Exception as exc:
            st.error(
                f"Event ingestion failed: {exc}"
            )

    st.divider()

    st.subheader(
        "Autonomous Event Processing"
    )

    st.caption(
        "If the background worker is running, "
        "pending events are processed automatically."
    )

    if st.button(
        "▶ Process One Pending Event Now"
    ):

        try:

            with st.spinner(
                "AI agent investigating incoming event..."
            ):

                result = events.process_one()

            if result:

                display_json(result)

            else:

                st.info(
                    "No pending events available."
                )

        except Exception as exc:
            st.error(str(exc))

    st.divider()

    st.subheader("Event Queue")

    if event_rows:

        st.dataframe(
            event_rows,
            hide_index=True,
            use_container_width=True
        )

    else:

        st.info(
            "No security events have been ingested."
        )

    if st.button(
        "🔄 Refresh Event Queue"
    ):
        st.rerun()


# ============================================================
# PAGE 9 - AGENT MEMORY
# ============================================================

elif page == "🧠 Agent Memory":

    st.title("Agent Memory")

    st.caption(
        "Retrieve relevant historical investigations "
        "for knowledge reuse"
    )

    st.info(
        "Historical investigations provide context. "
        "The agent must still verify current device "
        "information before taking action."
    )

    memory_query = st.text_input(
        "Search Past Investigations",
        value="malware DEV-104"
    )

    memory_limit = st.slider(
        "Maximum Results",
        min_value=1,
        max_value=10,
        value=5
    )

    if st.button(
        "🔎 Search Agent Memory",
        type="primary"
    ):

        try:

            memories = similar_cases(
                memory_query,
                limit=memory_limit
            )

            if not memories:

                st.warning(
                    "No matching historical investigations."
                )

            else:

                st.success(
                    f"Found {len(memories)} relevant records."
                )

                for index, memory in enumerate(
                    memories,
                    start=1
                ):

                    with st.expander(
                        f"{index}. {memory['run_id']} "
                        f"| Match Score: {memory['match_score']}"
                    ):

                        st.write(
                            "**Objective:**",
                            memory["objective"]
                        )

                        st.write(
                            "**Created:**",
                            memory["created_at"]
                        )

                        st.markdown(
                            "**Historical Summary**"
                        )

                        st.write(
                            memory["summary"]
                        )

        except Exception as exc:
            st.error(str(exc))

    st.divider()

    st.subheader(
        "Stored Investigation History"
    )

    completed_runs = rows("""
        SELECT id, objective, status, created_at
        FROM runs
        WHERE status='completed'
        ORDER BY created_at DESC
        LIMIT 100
    """)

    if completed_runs:

        st.dataframe(
            completed_runs,
            hide_index=True,
            use_container_width=True
        )

    else:

        st.info(
            "No completed investigations stored yet."
        )


# ============================================================
# PAGE 10 - EVALUATION LAB (TOOL + LIVE LLM RESULTS)
# ============================================================

elif page == "🧪 Evaluation Lab":
    st.title("AI Agent Evaluation Center")
    st.caption("Tool checks and real LLM investigation evaluations are reported separately.")

    tool_tab, llm_tab = st.tabs(["Tool Checks", "Live LLM Evaluations"])

    with tool_tab:
        st.subheader("Deterministic Tool Evaluation")
        st.info("These checks validate Python tools, not the quality of the model's decisions.")
        if st.button("Run Tool Checks", type="primary", key="evaluate_tools"):
            try:
                report = evaluate()
                st.session_state["tool_eval_report"] = report
            except Exception as exc:
                st.error(f"Tool evaluation failed: {exc}")

        report = st.session_state.get("tool_eval_report")
        if report:
            total = int(report.get("total", 0))
            passed = int(report.get("passed", 0))
            a, b, c = st.columns(3)
            a.metric("Checks", total)
            b.metric("Passed", passed)
            c.metric("Failed", total - passed)
            st.dataframe(report.get("checks", []), hide_index=True, use_container_width=True)
            st.download_button(
                "Download Tool Report", json.dumps(report, indent=2, default=str),
                file_name="tool_evaluation.json", mime="application/json",
                key="download_tool_eval",
            )
        st.code("python -m unittest discover -s tests -v", language="bash")

    with llm_tab:
        st.subheader("Real LLM Investigation Evaluation")
        st.info(
            "Run this evaluation in a separate terminal with the dashboard and "
            "worker stopped. It calls the real configured Ollama model using isolated test data."
        )
        st.code(
            "python -m opspilot.llm_evaluator --repeat 1",
            language="bash",
        )
        if st.button("Refresh Saved Results", key="refresh_llm_eval"):
            st.rerun()

        result_path = ROOT / "evaluation_results" / "latest.json"
        if not result_path.is_file():
            st.warning("No saved LLM evaluation found. Run the command above first.")
        else:
            try:
                report = json.loads(result_path.read_text(encoding="utf-8"))
                if not isinstance(report, dict) or not isinstance(report.get("results"), list):
                    raise ValueError("Unexpected evaluation report structure")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                st.error(f"Cannot read evaluation report: {exc}")
            else:
                results = report["results"]
                total = len(results)
                passed = sum(1 for r in results if r.get("passed") is True)
                rate = 100 * passed / total if total else 0.0
                a, b, c, d = st.columns(4)
                a.metric("Evaluations", total)
                b.metric("Passed", passed)
                c.metric("Failed", total - passed)
                d.metric("Pass Rate", f"{rate:.1f}%")
                st.progress(min(1.0, max(0.0, rate / 100)))
                st.caption(f"Model: {report.get('model', 'Unknown')} · Updated: {report.get('timestamp', 'Unknown')}")

                summary = [
                    {
                        "Scenario": r.get("name", r.get("scenario_id", "Unknown")),
                        "Repetition": r.get("repetition", 1),
                        "Passed": bool(r.get("passed", False)),
                        "Score %": r.get("score", 0),
                        "Run Status": r.get("run_status", "error"),
                        "Duration (s)": r.get("duration_seconds"),
                        "Tool Calls": len(r.get("tools_called") or []),
                        "Error": r.get("error", ""),
                    }
                    for r in results
                ]
                if summary:
                    st.dataframe(summary, hide_index=True, use_container_width=True)
                else:
                    st.info("Report contains no completed evaluations.")

                for i, item in enumerate(results, 1):
                    mark = "✅" if item.get("passed") is True else "❌"
                    title = item.get("name", item.get("scenario_id", "Scenario"))
                    with st.expander(f"{mark} {i}. {title}"):
                        if item.get("error"):
                            st.error(item["error"])
                        st.write("**Status:**", item.get("run_status", "Unknown"))
                        st.write("**Duration (s):**", item.get("duration_seconds", "—"))
                        st.write("**Executed or requested tools:**", item.get("tools_called", []))
                        st.markdown("**Checks**")
                        st.json(item.get("checks", {}))
                        st.markdown("**Final agent report**")
                        st.write(item.get("agent_report") or "No final report")
                        with st.expander("Full tool audit"):
                            st.json(item.get("audit", []))
                st.download_button(
                    "Download LLM Evaluation JSON",
                    json.dumps(report, indent=2, default=str),
                    file_name="llm_evaluation.json", mime="application/json",
                    key="download_llm_eval",
                )
                st.caption(
                    "Pass rate measures explicit scenario assertions; it is not a "
                    "general accuracy or hallucination score."
                )
