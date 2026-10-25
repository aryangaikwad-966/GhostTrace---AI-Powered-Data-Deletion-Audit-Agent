# GhostTrace evaluation report

Evaluation command: `python3 -B code/evaluation/main.py` (run from the repository root). The evaluator compares predictions with the participant-facing 32-row `dataset/sample_output.csv`; that file is not loaded by `code/main.py` or used for predictions.

## Results

- Public sample status accuracy: **32/32 (100.0%)**.
- Exact ordered step-sequence accuracy: **7/32 (21.9%)**.
- Exact step-object overlap (including step number and evidence ID): precision **112/156 (71.8%)**, recall **112/193 (58.0%)**, F1 **0.642**.
- Aligned step-field accuracy: **938/1,351 (69.4%)** across `step_no`, phase, system, resource, operation, state, and evidence ID. Missing/extra sequence positions count as incorrect for all seven fields.
- Full output contract validation: **518/518 rows**, exact header/order, valid JSON arrays and step objects; **0 contract errors** on the final run.
- Full-run predicted statuses: **156 COMPLETE, 270 INCOMPLETE, 92 NOT_APPLICABLE**.
- Team-authored authorization/identity cases: **6/6 passed**; standard-library unit tests: **6/6 passed**.

## Additional evaluation cases

The evaluator creates cases independently of the public sample:

| Case | Expected | Result |
|---|---:|---:|
| Direct English account-deletion request | authorized | pass |
| French `suppression définitive` request | authorized | pass |
| Japanese account-deletion request | authorized | pass |
| Data-copy/access request | not authorized | pass |
| Explicitly negated deletion request | not authorized | pass |
| Marketing unsubscribe request | not authorized | pass |

The unit tests also check that historical identity values are resolved only when their audit events are at or before `audit_at`; a post-cutoff snapshot is not used to associate the subject.

## Failures and improvements

The final sample run gets every status right, but only 7 complete step arrays exactly match. The largest remaining gaps are resource attribution and omitted verification rows where the participant-facing evidence does not link a specific resource to the subject. For example, the public expected account resources in cases 01, 02, and 04 are not present as identity-linked profile rows in the inspected evidence; the implementation does not copy those resource IDs from sample answers. Case 03's expected anonymized analytics resource also has no direct identifier in the available evidence. Some incomplete cases likewise miss a security verification resource or the sample's expected verification step ordering after an unlinked account resource is omitted.

During iteration, the parser was updated to read SQLite snapshots through SQLite, accept timestamp-prefixed JSON log lines and multiple service-log formats, use the latest non-future observation, apply the supplied policy CSV, and avoid linking an entire multi-subject PDF to each listed subject. Support messages now follow the supplied redaction rule. These evidence-linking and policy changes raised the final exact step-object F1 to 0.642; status performance is not a substitute for the unresolved step-level misses.

No organizer-only truth, hidden labels, or case-ID prediction shortcuts are used. Remaining uncertainty is deliberately reported rather than filled with guessed resource IDs or unsupported evidence.
