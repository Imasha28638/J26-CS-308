"""Run: py tests/test_pp1_public_cloudtrail_train_PROTO.py
No public dataset download required; uses small programmatically constructed fixture.
"""
from __future__ import annotations
import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from train_pp1_public_cloudtrail_PROTO import (
    REQUIRED, audit_inputs, check_folds, make_windows, read_import,
)
import numpy as np


FIELDS = sorted(REQUIRED)


def fixture(root, with_overlap=False):
    inp = root / 'in'
    inp.mkdir()
    (inp / 'ariel_ingestion_manifest_PROTO.json').write_text(json.dumps({
        'ready_for_experiment': True, 'train_test_event_id_overlap': 0,
    }), encoding='utf-8')
    train, test = [], []
    for split, sink, month in [('train', train, '03'), ('test', test, '04')]:
        for actor in range(9):
            for day in range(1, 5):
                for i in range(2):
                    positive = actor < 3 and i == 0
                    sink.append({
                        'session_id': f'actor{actor}',
                        'event_id': f'{split}_{actor}_{day}_{i}',
                        'event_time': f'2026-{month}-{day:02}T12:{i*10:02}:00Z',
                        'event_name': 'StopLogging' if positive else 'DescribeInstances',
                        'event_source': 'cloudtrail.amazonaws.com' if positive else 'ec2.amazonaws.com',
                        'read_only': 'false' if positive else 'true',
                        'error_code': '', 'aws_region': 'us-east-1',
                        'observed_positive_flag': str(int(positive)),
                        'candidate_attack_class': 'AttackA' if positive else '',
                        'scenario_id': 'AttackA' if positive else '',
                        'source_archive': 'train_labeled_a.zip' if split == 'train' else 'labeled_cloudtrail_a.zip',
                        'source_split': split,
                    })
    if with_overlap:
        test[0]['event_time'] = train[0]['event_time']
    for filename, rows in [('ariel_train_events_PROTO.csv', train), ('ariel_test_events_PROTO.csv', test)]:
        with (inp / filename).open('w', encoding='utf-8-sig', newline='') as fp:
            w = csv.DictWriter(fp, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
    return inp


class PublicCloudTrailTests(unittest.TestCase):
    def test_clean_import(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = fixture(root)
            x = read_import(inp / 'ariel_train_events_PROTO.csv', 'train')
            df, seq, scenarios = make_windows(x, 5)
            self.assertEqual(len(x), 72)
            self.assertEqual(len(df), 72)
            self.assertEqual(int(df.label_binary.sum()), 12)
            self.assertEqual(sum(bool(x) for x in scenarios), 12)
            self.assertEqual(len(seq), len(df))

    def test_audit_preserves_publisher_split(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = fixture(root)
            *_, audit = audit_inputs(inp, root / 'out', 5, 'actor-day', 'fail')
            self.assertEqual(audit['event_id_overlap'], 0)
            self.assertEqual(audit['original_overlapping_actor_time_windows'], 0)
            self.assertEqual(audit['actors_in_both_publisher_splits'], 9)
            self.assertEqual(audit['positive_oof_groups'], 12)

    def test_overlap_report_and_drop_train(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = fixture(root, with_overlap=True)
            *_, audit = audit_inputs(inp, root / 'out', 5, 'actor-day', 'fail')
            self.assertEqual(audit['original_overlapping_actor_time_windows'], 1)
            *_, audit2 = audit_inputs(inp, root / 'out', 5, 'actor-day', 'drop-train')
            self.assertEqual(audit2['removed_training_windows'], 1)

    def test_group_folds_no_group_leakage(self):
        from train_pp1_public_cloudtrail_PROTO import group_keys
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = fixture(root)
            train_df, seq, _, *_ = audit_inputs(inp, root / 'out', 5, 'actor-day', 'fail')
            groups = group_keys(train_df, 'actor-day')
            x = train_df[['event_count']].to_numpy()
            y = train_df.label_binary.to_numpy(dtype=int)
            folds, _ = check_folds(x, y, groups, 3, 4010)
            for fit, val in folds:
                self.assertFalse(set(groups[fit]) & set(groups[val]))
                self.assertEqual(set(y[fit]), {0, 1})
                self.assertEqual(set(y[val]), {0, 1})

    def test_reject_cross_split_event_ids(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = fixture(root)
            train_path = inp / 'ariel_train_events_PROTO.csv'
            test_path = inp / 'ariel_test_events_PROTO.csv'
            import pandas as pd
            tr = pd.read_csv(train_path, dtype=str).fillna('')
            te = pd.read_csv(test_path, dtype=str).fillna('')
            te.loc[0, 'event_id'] = tr.loc[0, 'event_id']
            te.to_csv(test_path, index=False)
            with self.assertRaisesRegex(ValueError, 'event-ID overlap'):
                audit_inputs(inp, root / 'out', 5, 'actor-day', 'fail')

    def test_mixed_window_any_positive(self):
        rows = [
            {'session_id': 'actor', 'event_id': '1', 'event_time': '2026-03-01T12:00:10Z',
             'event_name': 'DescribeInstances', 'event_source': 'ec2.amazonaws.com',
             'read_only': 'true', 'error_code': '', 'aws_region': 'us-east-1',
             'observed_positive_flag': '0', 'scenario_id': ''},
            {'session_id': 'actor', 'event_id': '2', 'event_time': '2026-03-01T12:00:20Z',
             'event_name': 'StopLogging', 'event_source': 'cloudtrail.amazonaws.com',
             'read_only': 'false', 'error_code': '', 'aws_region': 'us-east-1',
             'observed_positive_flag': '1', 'scenario_id': 'AttackA'},
        ]
        df, _, sc = make_windows(rows, 5)
        self.assertEqual(len(df), 1)
        self.assertEqual(int(df.label_binary.iloc[0]), 1)
        self.assertEqual(int(df.positive_event_count.iloc[0]), 1)
        self.assertEqual(sc[0]['AttackA'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
