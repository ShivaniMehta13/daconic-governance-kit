"""Two explicit host integration styles, not vendor-certified runtime connectors."""
import copy
from .observation import validate_trace


def structured_trace(metadata, input_payload, transformed_payload, outbound_payload):
    """Host snapshots JSON values immediately at its model-client hook."""
    trace = copy.deepcopy(metadata)
    for stage, payload in zip(("input", "transformed", "outbound"), (input_payload, transformed_payload, outbound_payload)):
        trace["stages"][stage]["availability"] = "present"
        trace["stages"][stage]["payload"] = copy.deepcopy(payload)
    return validate_trace(trace)


def event_trace(metadata, events):
    """Host assembles three complete JSON stage events, accepting any arrival order.

    Correlation and duplicate stages are validated. Source identities remain claims.
    Missing events remain unavailable; streaming fragments are not accepted.
    """
    trace = copy.deepcopy(metadata)
    seen = set()
    for stage in trace["stages"].values():
        stage["availability"] = "unavailable"
        stage.pop("payload", None)
    for event in events:
        if set(event) != {"interaction_id", "stage", "snapshot"}: raise ValueError("Invalid stage event")
        if event["interaction_id"] != trace["interaction_id"]: raise ValueError("Cross-interaction event")
        stage = event["stage"]
        if stage not in trace["stages"] or stage in seen: raise ValueError("Unknown or duplicate stage")
        seen.add(stage)
        trace["stages"][stage] = copy.deepcopy(event["snapshot"])
    return validate_trace(trace)
