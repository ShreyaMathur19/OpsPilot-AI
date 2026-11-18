# Internal Security Policy (synthetic demo data)

## Evidence and confidence
Assess severity using the observed alerts and device state. Do not claim a confirmed compromise based solely on failed logins, missing patches or suspicious timestamps. If sources are incomplete or contradictory, explicitly describe uncertainty and request further investigation.

## Critical malware incidents
Critical malware detections on an endpoint require an incident ticket and security-team escalation. Device quarantine may be appropriate after reviewing device evidence. Any quarantine action must receive explicit human approval. Never treat a blocked executable alone as conclusive evidence of compromise.

## Authentication anomalies
Repeated failed logins are a signal to investigate. Correlate them with endpoint alerts; do not assume an attack succeeded. Document evidence and alert the responsible team when risk merits escalation.

## Misconfiguration and exposed services
Exposed unauthorized services should be investigated and a remediation ticket raised when confirmed. Do not automatically quarantine for a configuration issue without additional evidence.

## Owner notifications
Owner notifications should describe observed evidence and next steps without asserting unverified facts. Notification messages in this demo go only to a local simulated outbox.

## Change safety
Ticket creation and simulated notification are low-risk actions. Endpoint quarantine is high-impact and must be approved by a human. The agent may recommend quarantine but cannot bypass the approval gate.
