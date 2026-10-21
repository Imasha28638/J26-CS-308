import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from copy import deepcopy

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from convert_pp1_member4_v2_PROTO import convert, validate_v2, load_cloudtrail_events
from validate_pp1_member4_v2_PROTO import check


def fixture():
    event = {'eventTime':'2024-07-31T13:06:24Z','eventName':'StopLogging',
             'eventSource':'cloudtrail.amazonaws.com','eventID':'abc-123', 'readOnly':False}
    f = {'finding_id':'d4587224fb6a08382ee01412', 'event_window_start_utc':'2024-07-31T13:05:00Z',
         'actor_hash':'f8488abb70e22d6da5e1', 'activity':'MALICIOUS_PATTERN',
         'predicted_binary':1,'stacking_score':0.90721,'model_disagreement':0.064462,
         'api_operations':{'StopLogging':1}, 'aws_services':['cloudtrail.amazonaws.com'],
         'event_count':1,'evidence_record_numbers':[1], 'attack_category':None}
    v1 = {'schema_version':'member2_to_member4_proto_v1','status':'PROTO_EVALUATION',
          'source':'member2_pp1_binary_stacking','score_type':'uncalibrated_model_score','findings':[f]}
    w = {'window_id':f['finding_id'], 'window_start_utc':f['event_window_start_utc'],
         'actor_hash':f['actor_hash'], 'predicted_activity':f['activity'],
         'predicted_binary':f['predicted_binary'], 'stacking_score':f['stacking_score'],
         'model_disagreement':f['model_disagreement'], 'api_operations':f['api_operations'],
         'aws_services':f['aws_services'], 'event_count':1, 'source_record_numbers':[1]}
    report = {'source_record_count':1,'decision_threshold':0.5,'windows':[w]}
    return v1, report, [event]


class V2ContractTests(unittest.TestCase):
    def test_single_stoplogging_with_missing_resource(self):
        v1, report, events = fixture()
        result = convert(v1, report, events, 'Data/Raw/stratus/stop.json', '0'*64)
        self.assertEqual([], validate_v2(result))
        f = result['findings'][0]
        self.assertEqual('CloudTrail', f['service'])
        self.assertEqual('StopLogging', f['event_name'])
        self.assertIsNone(f['resource_id'])
        self.assertEqual('Malicious', f['prediction'])
        self.assertEqual('uncalibrated_model_score', f['confidence_type'])
        self.assertEqual('Data/Raw/stratus/stop.json#record=1', f['evidence_reference'])
        self.assertEqual(['abc-123'], f['evidence_event_ids'])

    def test_extract_unique_arn_only_when_original_event_contains_one(self):
        v1, report, events = fixture()
        events[0]['resources'] = [{'ARN': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/test'}]
        f = convert(v1,report,events,'original.json','0'*64)['findings'][0]
        self.assertTrue(f['resource_id'].startswith('arn:aws:cloudtrail'))
        events[0]['resources'].append({'ARN':'arn:aws:s3:::other'})
        f = convert(v1,report,events,'original.json','0'*64)['findings'][0]
        self.assertIsNone(f['resource_id'])
        self.assertEqual(2, len(f['resource_ids']))

    def test_reject_source_operation_mismatch(self):
        v1, report, events = fixture()
        events[0]['eventName'] = 'DeleteTrail'
        with self.assertRaisesRegex(ValueError, 'source events do not match'):
            convert(v1,report,events,'original.json','0'*64)

    def test_reject_prediction_mismatch(self):
        v1, report, events = fixture()
        v1['findings'][0]['predicted_binary'] = 0
        with self.assertRaisesRegex(ValueError, 'differs|inconsistent|match'):
            convert(v1,report,events,'original.json','0'*64)

    def test_validator_rejects_unmarked_score_semantics(self):
        v1, report, events = fixture()
        out = convert(v1,report,events,'original.json','0'*64)
        out['findings'][0]['confidence_type'] = 'calibrated_probability'
        self.assertTrue(validate_v2(out))

    def test_empty_findings_with_empty_windows(self):
        v1, report, events = fixture()
        v1['findings'] = []
        report['windows'] = []
        with self.assertRaisesRegex(ValueError, 'cover'):
            convert(v1,report,events,'original.json','0'*64)

    def test_multi_operation_represents_only_primary(self):
        v1, report, events = fixture()
        second = {'eventTime':'2024-07-31T13:06:25Z','eventName':'DescribeTrails',
                  'eventSource':'cloudtrail.amazonaws.com','eventID':'abc-124', 'readOnly': True}
        events.append(second)
        f = v1['findings'][0]
        f['api_operations'] = {'StopLogging':1,'DescribeTrails':1}
        f['event_count'] = 2
        f['evidence_record_numbers'] = [1,2]
        w = report['windows'][0]
        w['api_operations'] = deepcopy(f['api_operations'])
        w['event_count'] = 2
        w['source_record_numbers'] = [1,2]
        report['source_record_count'] = 2
        out = convert(v1,report,events,'original.json','0'*64)
        self.assertEqual('representative_highest_count', out['findings'][0]['event_name_type'])
        self.assertEqual('DescribeTrails', out['findings'][0]['event_name'])
        self.assertEqual('original.json#records=1,2',out['findings'][0]['evidence_reference'])
        self.assertEqual([], validate_v2(out))

    def test_complete_file_reconciliation_and_sha(self):
        v1, report, events = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / 'input.json'
            p.write_text(json.dumps({'Records':events}), encoding='utf-8')
            out = convert(v1,report,events,p.name,hashlib.sha256(p.read_bytes()).hexdigest())
            vp = pathlib.Path(tmp) / 'v1.json'; vp.write_text(json.dumps(v1),encoding='utf-8')
            rp = pathlib.Path(tmp) / 'report.json'; rp.write_text(json.dumps(report),encoding='utf-8')
            self.assertEqual([], check(out,p,rp,vp))
            p.write_text(json.dumps({'Records':[dict(events[0], eventName='DeleteTrail')]}),encoding='utf-8')
            self.assertTrue(check(out,p,rp,vp))


if __name__=='__main__':
    unittest.main()
