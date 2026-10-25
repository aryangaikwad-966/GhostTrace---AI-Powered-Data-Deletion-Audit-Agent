#!/usr/bin/env python3
"""Reproducible public-sample evaluator and output-contract checks."""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
import main as agent


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_agent():
    by_email, by_id = agent.load_identities()
    history = agent.load_audit_history()
    evidence = {}
    for eid, path, captured_at, _kind in agent.list_evidence_files():
        evidence[eid] = {"obs": agent.parse_evidence_file(eid, path, captured_at), "_captured_at": captured_at}
    activities = read_csv(agent.DATASET / "system_activity.csv")
    return by_email, by_id, history, evidence, activities


def validate(case_id, status, steps):
    errors = []
    if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
        errors.append(f"{case_id}: disallowed status")
    if status == "NOT_APPLICABLE" and steps:
        errors.append(f"{case_id}: NOT_APPLICABLE must use []")
    if [s.get("step_no") for s in steps] != list(range(1, len(steps) + 1)):
        errors.append(f"{case_id}: nonconsecutive step numbers")
    allowed = {
        "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"), "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
        "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"), "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
        "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"), "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
        "DELETE_RECORD": ("REMEDIATION", "ABSENT"), "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
        "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"), "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
        "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"), "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
        "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"), "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
        "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
    }
    phases = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    order = []
    sort_keys = []
    for s in steps:
        expected = allowed.get(s.get("operation"))
        if not expected or expected != (s.get("phase"), s.get("state")):
            errors.append(f"{case_id}: invalid operation/phase/state")
        if set(s) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}:
            errors.append(f"{case_id}: step schema mismatch")
        if not isinstance(s.get("resource_id"), str) or not s.get("resource_id"):
            errors.append(f"{case_id}: empty resource_id")
        order.append(phases.get(s.get("phase"), -1))
        sort_keys.append((phases.get(s.get("phase"), -1), list(allowed).index(s["operation"]) if s.get("operation") in allowed else -1, s.get("system_id", ""), s.get("resource_id", "")))
        if status == "COMPLETE" and (s.get("phase") != "VERIFICATION" or not s.get("evidence_id")):
            errors.append(f"{case_id}: COMPLETE step is not evidence-backed verification")
        if status == "INCOMPLETE" and s.get("phase") in {"REMEDIATION", "VERIFICATION"} and s.get("evidence_id"):
            errors.append(f"{case_id}: future step contains evidence_id")
        if s.get("phase") == "FINDING" and not s.get("evidence_id"):
            errors.append(f"{case_id}: finding lacks evidence_id")
    if order != sorted(order):
        errors.append(f"{case_id}: phase sequence is unordered")
    if sort_keys != sorted(sort_keys):
        errors.append(f"{case_id}: operation/system/resource ordering is invalid")
    return errors


def validate_full_output():
    path = ROOT / "output.csv"
    requests = read_csv(agent.DATASET / "deletion_requests.csv")
    with open(path, newline="", encoding="utf-8") as f:
        header = csv.DictReader(f).fieldnames
    rows = read_csv(path)
    errors = []
    if header != ["case_id", "deletion_status", "steps_json"]:
        errors.append(f"output.csv header mismatch: {header}")
    expected_ids = sorted(r["case_id"] for r in requests)
    actual_ids = [r["case_id"] for r in rows]
    if actual_ids != expected_ids:
        errors.append(f"output.csv IDs/count/order mismatch: {len(actual_ids)} rows, expected {len(expected_ids)}")
    for row in rows:
        try:
            steps = json.loads(row["steps_json"])
        except Exception:
            errors.append(f"{row.get('case_id')}: invalid steps_json")
            continue
        errors.extend(validate(row["case_id"], row["deletion_status"], steps))
    return len(rows), errors


def custom_tests():
    examples = [
        ("plain deletion", "Please permanently delete my account.", True),
        ("French erasure", "Je demande la suppression définitive de mon compte.", True),
        ("Japanese erasure", "アカウントを削除してください。", True),
        ("access only", "Please send me a copy of my data.", False),
        ("explicit negation", "Please do not delete my account; I only want to change my email.", False),
        ("marketing opt-out", "Unsubscribe me from marketing emails.", False),
    ]
    return [(name, want, agent.is_deletion_authorized(text)) for name, text, want in examples]


def main():
    full_count, full_errors = validate_full_output()
    samples = read_csv(agent.DATASET / "sample_deletion_requests.csv")
    truth_rows = read_csv(agent.DATASET / "sample_output.csv")
    truth = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in truth_rows}
    by_email, by_id, history, evidence, activities = load_agent()
    predictions = {}
    contract_errors = []
    for case in samples:
        status, steps = agent.analyze_case(case, by_email, by_id, history, evidence, activities)
        predictions[case["case_id"]] = (status, steps)
        contract_errors.extend(validate(case["case_id"], status, steps))

    status_ok = sum(predictions[k][0] == truth[k][0] for k in truth)
    exact_cases = sum(predictions[k][1] == truth[k][1] for k in truth)
    pred_steps = [json.dumps(s, sort_keys=True) for _, steps in predictions.values() for s in steps]
    true_steps = [json.dumps(s, sort_keys=True) for _, steps in truth.values() for s in steps]
    pred_counts, true_counts = Counter(pred_steps), Counter(true_steps)
    step_tp = sum((pred_counts & true_counts).values())
    step_precision = step_tp / max(1, len(pred_steps))
    step_recall = step_tp / max(1, len(true_steps))
    step_f1 = 2 * step_precision * step_recall / max(1e-12, step_precision + step_recall)
    fields = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    field_total = field_ok = 0
    for case_id in truth:
        ps, ts = predictions[case_id][1], truth[case_id][1]
        for i in range(max(len(ps), len(ts))):
            for key in fields:
                field_total += 1
                field_ok += int(i < len(ps) and i < len(ts) and ps[i].get(key) == ts[i].get(key))
    field_accuracy = field_ok / max(1, field_total)
    custom = custom_tests()
    print(f"Sample cases: {len(truth)}")
    print(f"Status accuracy: {status_ok}/{len(truth)} ({status_ok / len(truth):.1%})")
    print(f"Exact step sequence: {exact_cases}/{len(truth)} ({exact_cases / len(truth):.1%})")
    print(f"Step micro P/R/F1: {step_precision:.3f}/{step_recall:.3f}/{step_f1:.3f} ({step_tp}/{len(pred_steps)} predicted; {len(true_steps)} expected)")
    print(f"Aligned step-field accuracy: {field_ok}/{field_total} ({field_accuracy:.1%})")
    print(f"Contract errors: {len(contract_errors)}")
    for error in contract_errors[:25]:
        print("CONTRACT", error)
    print(f"Full output rows: {full_count}/518; contract errors: {len(full_errors)}")
    for error in full_errors[:25]:
        print("FULL_OUTPUT", error)
    print(f"Custom tests: {sum(got == want for _, want, got in custom)}/{len(custom)}")
    for name, want, got in custom:
        print(f"TEST {name}: expected={want} actual={got} {'PASS' if want == got else 'FAIL'}")
    print("MISMATCHES:")
    for case_id in truth:
        ps, ts = predictions[case_id], truth[case_id]
        if ps != ts:
            pset, tset = Counter(json.dumps(s, sort_keys=True) for s in ps[1]), Counter(json.dumps(s, sort_keys=True) for s in ts[1])
            missing = list((tset - pset).elements())
            extra = list((pset - tset).elements())
            print(f"{case_id}: status {ps[0]}/{ts[0]}; steps {len(ps[1])}/{len(ts[1])}; missing={missing[:2]}; extra={extra[:2]}")
    return 1 if contract_errors or full_errors or any(want != got for _, want, got in custom) else 0


if __name__ == "__main__":
    raise SystemExit(main())
