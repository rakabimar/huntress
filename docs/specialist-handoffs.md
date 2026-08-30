# Specialist handoffs

The orchestrator persists a bounded task with creator/assigned roles, run/session, optional Lead/Hypothesis, goal and small input summary. A specialist returns structured observations, hypotheses, recommended next test, evidence/Lead refs, confidence and unresolved questions.

Handoffs grant no authority: specialists cannot activate programs, change ROE, approve ASK actions or validate their own findings. Status is `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, or `CANCELLED`; duration, tokens and cost are optional telemetry.
