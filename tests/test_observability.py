def test_specialist_handoff_and_agent_metrics_are_persistent(db):
    session = db.start_session("pytest", "orchestrator", "acme-test")
    run = db.start_autonomy_run(session.id, "budget_exhausted", {"max_total_requests": 5})
    lead = db.add_lead("source lead")
    task = db.create_specialist_task(
        created_by_role="orchestrator", assigned_role="whitebox-audit-specialist",
        goal="resolve authorization path", session_id=session.id,
        autonomy_run_id=run.id, lead_id=lead.id, input_summary="bounded source context",
    )
    turn = db.start_agent_turn(
        session_id=session.id, role="orchestrator", runtime="pytest", model="fixture",
        autonomy_run_id=run.id, skills_loaded=["source-authorization-analysis"],
        tools_available_count=25,
    )
    db.record_tool_call(session_id=session.id, role="orchestrator", tool="create_specialist_task",
                        success=True, agent_turn_id=turn["id"], autonomy_run_id=run.id)
    db.record_skill_usage(session_id=session.id, role="whitebox-audit-specialist",
                          skill="source-authorization-analysis", autonomy_run_id=run.id,
                          specialist_task_id=task["id"], lead_id=lead.id)
    specialist = db.start_session("pytest", "whitebox-audit-specialist", "acme-test")
    db.update_specialist_task(task["id"], status="RUNNING", claimed_session_id=specialist.id)
    db.update_specialist_task(task["id"], status="COMPLETED", result_summary="central control unresolved",
                              result_refs=[lead.public_id], tokens=100, cost=0.01)
    db.complete_agent_turn(turn["id"], input_tokens=50, output_tokens=25, estimated_cost=0.02,
                           outcome="delegated")
    latest = db.latest_agent_turn(session.id)
    assert latest and latest["id"] == turn["id"]
    db.complete_agent_turn(latest["id"], input_tokens=60, output_tokens=30, cached_tokens=200,
                           estimated_cost=0.03, outcome="provider_reconciled")
    metrics = db.hunt_metrics(run.id)
    assert metrics["specialist_tasks"] == 1 and metrics["tool_calls"] == 1
    assert metrics["tokens"] == 90 and metrics["cached_tokens"] == 200 and metrics["cost"] == 0.03
    assert metrics["skill_usage_events"] == 1 and metrics["skills_used"] == ["source-authorization-analysis"]
    assert db.list_specialist_tasks(run.id)[0]["status"] == "COMPLETED"
