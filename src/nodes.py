"""
The three node functions: static_check -> dynamic_confirm -> decide.
Pure functions of ReachState -> ReachState so each is unit-testable in
isolation without spinning up the graph. Conditional-edge logic (should_*)
lives here too since it's tightly coupled to node output shape; the graph
wiring itself is in pipeline.py.
"""
from __future__ import annotations

from .dynamic_harness import EntryPointDriver, entry_point_param_names, patch_flagged_function, InvocationLog
from .graph_builder import build_graph
from .hypothesis import generate_hypothesis
from .schemas import ReachState, TraceStep

MAX_ATTEMPTS = 3  # 1 initial + 2 revised retries, per problem-statement.md Section 3


def static_check_node(state: ReachState) -> ReachState:
    target = state["target"]
    graph = build_graph(state["target_app_root"])
    flagged_qualname = f"{target.flagged_module}.{target.flagged_function}"

    found_path = None
    matched_entry = None
    for entry in target.entry_points:
        path = graph.find_path(entry, flagged_qualname)
        if path:
            found_path, matched_entry = path, entry
            break

    trace = list(state.get("trace", []))
    trace.append(TraceStep(
        stage="static",
        detail=(f"Path found: {' -> '.join(found_path)}" if found_path
                else f"No path from any of {target.entry_points} to {flagged_qualname}"),
    ))

    return {
        **state,
        "static_path": found_path,
        "matched_entry_point": matched_entry,
        "trace": trace,
        "retry_count": 0,
        "hypothesis_attempts": [],
        "dynamic_fired": False,
    }


def dynamic_confirm_node(state: ReachState) -> ReachState:
    target = state["target"]
    trace = list(state.get("trace", []))
    attempts = list(state.get("hypothesis_attempts", []))
    retry_count = state.get("retry_count", 0)
    entry_point = state["matched_entry_point"]

    driver = EntryPointDriver(state["target_app_root"])

    entry_module, _, entry_func = entry_point.rpartition(".")
    entry_params = None
    if target.driver_kind == "callable":
        try:
            entry_params = entry_point_param_names(entry_module, entry_func)
        except Exception as exc:
            trace.append(TraceStep(stage="dynamic", detail=f"Could not introspect entry point signature: {exc}"))

    try:
        hyp = generate_hypothesis(
            cve_id=target.cve_id,
            advisory_summary=target.advisory_summary,
            flagged_function=target.flagged_function,
            function_signature=target.function_signature,
            entry_point=entry_point,
            driver_kind=target.driver_kind,
            prior_attempts=attempts,
            entry_point_params=entry_params,
        )
    except Exception as exc:  # malformed/mismatched model output
        attempts.append(f"[REJECTED - shape mismatch] {exc}")
        trace.append(TraceStep(stage="hypothesis", detail=f"Attempt {retry_count + 1} rejected: {exc}"))
        return {
            **state,
            "dynamic_fired": False,
            "hypothesis_attempts": attempts,
            "retry_count": retry_count + 1,
            "trace": trace,
        }

    attempts.append(f"{hyp.reasoning} :: {hyp.hypothesis_input}")
    trace.append(TraceStep(stage="hypothesis", detail=f"Attempt {retry_count + 1}: {hyp.reasoning}"))

    with patch_flagged_function(target.flagged_module, target.flagged_function) as log:
        try:
            if target.driver_kind == "flask_route" and target.flask_app_import:
                route_meta = target.entry_point_routes.get(entry_point, {})
                driver.drive_flask_route(
                    flask_app_import=target.flask_app_import,
                    route=route_meta.get("route", "/"),
                    method=route_meta.get("method", "GET"),
                    hypothesis_input=hyp.hypothesis_input,
                )
            elif target.driver_kind == "fastapi_route" and target.fastapi_app_import:
                route_meta = target.entry_point_routes.get(entry_point, {})
                driver.drive_fastapi_route(
                    fastapi_app_import=target.fastapi_app_import,
                    route=route_meta.get("route", "/"),
                    method=route_meta.get("method", "GET"),
                    hypothesis_input=hyp.hypothesis_input,
                )
            else:
                driver.drive_callable(entry_module, entry_func, hyp.hypothesis_input)
        except Exception as exc:
            trace.append(TraceStep(stage="dynamic", detail=f"Driver raised (not itself conclusive): {exc}"))

    trace.append(TraceStep(stage="dynamic", detail=f"Flagged function fired: {log.fired}"))

    def _input_survived_intact(hypothesis_input: dict, log: InvocationLog) -> bool:
        """Cheap fidelity check: did the values we hypothesized actually reach
        the flagged function unmodified, or did something upstream sanitize/
        escape/truncate them before the call? A function firing with a
        neutered payload is a different (weaker) signal than firing with the
        exact malicious input intact."""
        if not log.call_kwargs:
            return False
        observed = log.call_kwargs[-1]  # most recent call
        for key, expected in hypothesis_input.items():
            actual = observed.get(key)
            if isinstance(expected, str) and isinstance(actual, str):
                if expected not in actual and actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    intact = log.fired and _input_survived_intact(hyp.hypothesis_input, log)
    if log.fired and not intact:
        trace.append(TraceStep(
            stage="dynamic",
            detail="Flagged function fired, but the hypothesized payload was "
                   "altered before it arrived — possible sanitization upstream. "
                   "Treating as weak signal, not full confirmation.",
        ))

    return {
        **state,
        "dynamic_fired": log.fired,
        "hypothesis_attempts": attempts,
        "retry_count": retry_count + 1,
        "trace": trace,
    }


def decide_node(state: ReachState) -> ReachState:
    trace = list(state.get("trace", []))
    if state.get("static_path") is None:
        label = "Not-Reachable"
    elif state.get("dynamic_fired"):
        label = "Confirmed-Reachable"
    else:
        label = "Static-Match-Only"
    trace.append(TraceStep(stage="decide", detail=f"Final label: {label}"))
    return {**state, "label": label, "trace": trace}


def should_attempt_dynamic(state: ReachState) -> str:
    return "dynamic_confirm" if state.get("static_path") else "decide"


def should_retry(state: ReachState) -> str:
    if state.get("dynamic_fired"):
        return "decide"
    if state.get("retry_count", 0) >= MAX_ATTEMPTS:
        return "decide"
    return "dynamic_confirm"
