"""Smoke tests for exact production training-feature reuse and CSV-to-CloudTrail export.

Requires the ORIGINAL train_pp1_binary_stack.py alongside infer_pp1_cloudtrail.py
when tests are extracted into the user's project root.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier

SRC = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0,str(SRC))
import infer_pp1_cloudtrail as inf
import train_pp1_binary_stack as training


class InferenceTests(unittest.TestCase):
    def test_exact_saved_feature_contract(self):
        self.assertEqual(inf.FEATURES,training.FEATURES)
        self.assertEqual(inf.SEQ_DIM,17)
        self.assertEqual(inf.MAX_SEQ,40)

    def test_event_records_and_order(self):
        events = inf.parse_cloudtrail(Path(__file__).resolve().parents[1]/'Data'/'Demo'/'example_cloudtrail_synthetic.json')
        norm, warnings = inf.normalize(events)
        meta,features,seq,lengths = inf.build_windows(norm,5)
        self.assertEqual(len(events),4)
        self.assertEqual(features.shape,(1,len(training.FEATURES)))
        self.assertEqual(seq.shape,(1,training.MAX_SEQ,training.SEQ_DIM))
        self.assertEqual(meta[0]['api_operations']['StopLogging'],1)
        self.assertEqual(lengths.tolist(),[4])
        self.assertEqual(warnings,[])

    def test_malformed_readonly_is_rejected(self):
        event={"eventTime":"2026-07-01T00:00:00Z","eventName":"ListBuckets","eventSource":"s3.amazonaws.com"}
        with self.assertRaisesRegex(ValueError,'readOnly missing'):
            inf.normalize([event])

    def test_minimal_artifact_loading_and_inference(self):
        rng=np.random.default_rng(19)
        x=rng.normal(size=(65,len(training.FEATURES)))
        y=np.asarray([0,1]*32+[0])
        models={
            'Random Forest':RandomForestClassifier(n_estimators=8,random_state=1,n_jobs=1),
            'LightGBM':LGBMClassifier(n_estimators=6,verbose=-1,num_leaves=5,min_child_samples=3,n_jobs=1),
            'XGBoost':XGBClassifier(n_estimators=6,max_depth=2,tree_method='hist',eval_metric='logloss',n_jobs=1),
        }
        for model in models.values():model.fit(x,y)
        pp=np.column_stack([m.predict_proba(x)[:,1] for m in models.values()]+[rng.uniform(0,1,len(x))])
        meta=LogisticRegression(max_iter=200).fit(pp,y)
        with tempfile.TemporaryDirectory() as d:
            tmp=Path(d)
            joblib.dump({'models':models,'meta':meta,'features':training.FEATURES},tmp/inf.MODEL_FILENAME)
            model=training.WindowLSTM()
            torch.save({'state_dict':model.state_dict(),'sequence_dim':training.SEQ_DIM,'max_seq':training.MAX_SEQ},tmp/inf.LSTM_FILENAME)
            path=Path(__file__).resolve().parents[1]/'Data'/'Demo'/'example_cloudtrail_synthetic.json'
            result,handoff=inf.run(path,tmp,tmp/'out.json')
            self.assertEqual(result['source_record_count'],4)
            self.assertEqual(result['window_count'],1)
            self.assertEqual(len(result['windows'][0]['model_scores']),4)
            self.assertTrue((tmp/'out.json').is_file())
            self.assertTrue(handoff.is_file())
            self.assertEqual(result['windows'][0]['research_attack_category'],None)
            self.assertNotIn('event_ids',result['windows'][0])
            result_with_ids,_=inf.run(path,tmp,tmp/'out_with_ids.json',include_event_ids=True)
            self.assertEqual(len(result_with_ids['windows'][0]['event_ids']),4)


if __name__=='__main__': unittest.main()
