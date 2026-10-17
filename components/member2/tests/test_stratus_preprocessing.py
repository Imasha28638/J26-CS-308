import importlib.util
import json
import sys
import tempfile
from pathlib import Path

MODULE = Path(__file__).parents[1] / "src" / "preprocess_stratus_detonations.py"
spec = importlib.util.spec_from_file_location("stratus_script", MODULE)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_rule_matching_and_errors():
    rules = {"aws.persistence.iam-create-admin-user": {"research_class": "Persistence", "event_names": ["CreateUser"]}}
    with tempfile.TemporaryDirectory() as d:
        file = Path(d) / "aws.persistence.iam-create-admin-user.json"
        inputs = [
            {"eventID": "a", "eventName": "CreateUser", "eventTime": "2024-01-01T00:00:00Z"},
            {"eventID": "b", "eventName": "GetCallerIdentity", "eventTime": "2024-01-01T00:00:01Z"},
            {"eventID": "c", "eventName": "CreateUser", "errorCode": "AccessDenied"},
        ]
        file.write_text(json.dumps(inputs), encoding="utf-8")
        rows = [module.normalize(e, file, i) for i, e in enumerate(module.parse_events(file), 1)]
        module.audit_and_classify(rows, rules)
        assert [r["label_status"] for r in rows] == ["review_candidate", "not_selected", "review_candidate"]
        assert rows[2]["outcome"] == "api_error"
        assert all(r["exclude_from_training"] == 1 for r in rows)


def test_case_sensitive_json_keys():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "aws.defense-evasion.cloudtrail-stop.json"
        p.write_text(json.dumps([{"eventName":"StopLogging","requestParameters":{"tag":1,"Tag":2}}]))
        events = module.parse_events(p)
        assert events[0]["requestParameters"] == {"tag": 1, "Tag": 2}


if __name__ == "__main__":
    test_rule_matching_and_errors()
    test_case_sensitive_json_keys()
    print("All tests passed")
