"""
Wires the three nodes into a LangGraph StateGraph per the conditional edges
in problem-statement.md Section 3:

  static_check --(path found?)--> dynamic_confirm --(fired or retries exhausted?)--> decide
                --(no path)------------------------------------------------------> decide

`run_pipeline` is the function Engineer B's CLI should import — it is the
only public surface of this module and it returns exactly the EngineOutput
shape from the interface contract.
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes import (
    decide_node,
    dynamic_confirm_node,
    should_attempt_dynamic,
    should_retry,
    static_check_node,
)
from .schemas import CVETarget, EngineOutput, ReachState


def build_pipeline():
    graph = StateGraph(ReachState)
    graph.add_node("static_check", static_check_node)
    graph.add_node("dynamic_confirm", dynamic_confirm_node)
    graph.add_node("decide", decide_node)

    graph.add_edge(START, "static_check")
    graph.add_conditional_edges(
        "static_check",
        should_attempt_dynamic,
        {"dynamic_confirm": "dynamic_confirm", "decide": "decide"},
    )
    graph.add_conditional_edges(
        "dynamic_confirm",
        should_retry,
        {"dynamic_confirm": "dynamic_confirm", "decide": "decide"},
    )
    graph.add_edge("decide", END)

    return graph.compile()


def run_pipeline(target: CVETarget, target_app_root: str) -> EngineOutput:
    app = build_pipeline()
    final_state = app.invoke({
        "target": target,
        "target_app_root": target_app_root,
        "trace": [],
    })
    return EngineOutput(
        cve_id=target.cve_id,
        label=final_state["label"],
        trace=final_state["trace"],
        static_path=final_state.get("static_path"),
        hypothesis_attempts=final_state.get("hypothesis_attempts", []),
    )
