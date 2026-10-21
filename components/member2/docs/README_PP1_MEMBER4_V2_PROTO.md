# PP1 Member 2 -> Member 4: Proposed v2 interface

This package **adds** an adapter to the current validated v1 handoff. It does not modify training, models, inference, or thresholds. Member 4 should explicitly approve the nullable resource and score semantics before freezing the interface.

## Install

Extract the ZIP at the Research Project root; `src/` and `contracts/` will be added. Existing files remain unchanged.

## Convert existing Stratus `StopLogging` inference

```powershell
py src/convert_pp1_member4_v2_PROTO.py `
  --handoff "Data/Experiments/pp1_inference/stratus_stop_mixed_PROTO_member4_PROTO.json" `
  --inference-report "Data/Experiments/pp1_inference/stratus_stop_mixed_PROTO.json" `
  --source-events "Data/Raw/data/raw/stratus/docs/detonation-logs/aws.defense-evasion.cloudtrail-stop.json" `
  --output "Data/Experiments/pp1_member4_contract_PROTO/stratus_stop_member4_v2_PROTO.json"
```

It uses the original CloudTrail source to verify API operation counts and obtain resource ARNs only when unambiguous. Missing ARN = `null`; no identifier is invented.

## Validate v2 against all original evidence

```powershell
py src/validate_pp1_member4_v2_PROTO.py `
  --handoff "Data/Experiments/pp1_member4_contract_PROTO/stratus_stop_member4_v2_PROTO.json" `
  --source-events "Data/Raw/data/raw/stratus/docs/detonation-logs/aws.defense-evasion.cloudtrail-stop.json" `
  --inference-report "Data/Experiments/pp1_inference/stratus_stop_mixed_PROTO.json" `
  --original-handoff "Data/Experiments/pp1_inference/stratus_stop_mixed_PROTO_member4_PROTO.json" `
  --output "Data/Experiments/pp1_member4_contract_PROTO/validation_v2_PROTO.json"
```

## Interpretation and contract rules

| v2 key | Meaning | Important qualification |
|---|---|---|
| finding_id | Same stable window finding ID as v1 | Unique within report; include input identity for cross-file deduplication |
| timestamp | UTC start of detection window | **Not** necessarily the API execution timestamp; `timestamp_type=window_start_utc` |
| entity_id | Pseudonymous actor group | `actor_hash:...`; **not** an actual AWS IAM ARN. Grouping may be principal- or source-IP-based |
| resource_id | Single verified resource ARN in original CloudTrail `resources` | `null` if absent or ambiguous; `resource_ids` preserves all verified ARNs |
| service | Human-readable name for representative eventSource | Full `event_source` and `aws_services` preserved |
| event_name | Observed operation; representative if multiple operations | `event_name_type` tells the consumer whether a window has multiple operations; `api_operations` carries full counts |
| prediction | `Benign` or `Malicious` | Binary classifier only; labels model output, not a verified incident |
| confidence | Numerically equal to original `stacking_score` | **Uncalibrated** model score, **not** probability of compromise; `confidence_type=uncalibrated_model_score` |
| evidence_reference | Original file path and **1-based** record indices | e.g. `path/to/file.json#record=1`; not a clickable HTTP URL |
| evidence_event_ids | Genuine native CloudTrail event IDs when present | Empty when original logs omit eventID |
| evidence_source_sha256 | SHA256 of complete original file | Evidence integrity; v2 validator can verify source file bytes |
| attack_category | `null` | No multiclass inference performed |

### Interface decisions Member 4 must confirm

1. `resource_id` can be `null`; evidence must not be invented.
2. `entity_id` can be a pseudonymous actor-group key instead of an actual AWS IAM user or role; for the final integration, identity mapping must come from authorized source records with appropriate access controls.
3. `confidence` is an uncalibrated ML score. Member 4 must **not** treat it as a calibrated probability, or automatically use it as an overall risk score.
4. For multi-operation windows, `event_name` is a representative event; Member 4 should display the full `api_operations` map when possible.
5. `timestamp` is the **window start**, and `evidence_reference` is a local evidence locator; the original file must be available to retrieve it.
6. The v2 document is an **envelope** containing `findings[]`; Member 4 must confirm whether their application expects this or an array of individual findings.

For sharing through GitHub, publish scripts, contracts, and redacted examples. Do not publish original AWS identities, sensitive resource ARNs, or private evidence paths without authorization.

## Tests

```powershell
py -m unittest discover -s tests -p "test_pp1_member4_v2_PROTO.py" -v
```

A validator PASS establishes data-contract consistency. It does not certify the performance of the underlying detector.
