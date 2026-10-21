"""Quick automated tests using small isolated CSV fixtures."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from report_pp1_public_scenarios_PROTO import run


class TestPerModelScenario(unittest.TestCase):
    def make_files(self,root):
        base=root/'base';base.mkdir()
        weighted=root/'weighted';weighted.mkdir()
        frame=pd.DataFrame([
            dict(session_id='a',window_start='2026-01-01T00:00:00Z',label_binary=1,publisher_attack_scenarios='A|B',
                 predicted_binary=0,prob_Random_Forest=.4,prob_LightGBM=.8,prob_XGBoost=.3,prob_LSTM=.2,stacked_malicious_score=.04),
            dict(session_id='b',window_start='2026-01-01T00:00:00Z',label_binary=1,publisher_attack_scenarios='B',
                 predicted_binary=0,prob_Random_Forest=.4,prob_LightGBM=.8,prob_XGBoost=.3,prob_LSTM=.2,stacked_malicious_score=.04),
            dict(session_id='c',window_start='2026-01-01T00:00:00Z',label_binary=0,publisher_attack_scenarios='',
                 predicted_binary=0,prob_Random_Forest=.1,prob_LightGBM=.1,prob_XGBoost=.1,prob_LSTM=.1,stacked_malicious_score=.01),
        ])
        frame.to_csv(base/'public_test_predictions_PROTO.csv',index=False)
        report={'test_windows':3,'positive_test_windows':2,'scenarios_seen_in_training':['A'],'model_metrics':{}}
        (base/'public_experiment_report_PROTO.json').write_text(json.dumps(report))
        pd.DataFrame([
            dict(scenario='A',positive_test_windows=1,detected_positive_windows=0),
            dict(scenario='B',positive_test_windows=2,detected_positive_windows=0),
        ]).to_csv(base/'public_attack_scenario_recall_PROTO.csv',index=False)
        wf=frame.copy();wf['candidate_stacking_score']=[.75,.9,.02]
        wf.to_csv(weighted/'weighted_public_test_predictions_PROTO.csv',index=False)
        return base,weighted

    def test_report_and_double_membership(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); base,w=self.make_files(root)
            result=run(base,root/'output',w)
            self.assertEqual(result['unique_attack_containing_windows'],2)
            self.assertEqual(result['scenario_window_occurrences'],3)
            metrics={m['model']:m for m in result['model_metrics']}
            self.assertEqual(metrics['LightGBM']['tp'],2)
            self.assertEqual(metrics['Stacking ensemble']['tp'],0)
            self.assertEqual(metrics['Weighted stacking candidate']['tp'],2)
            by=pd.read_csv(root/'output'/'public_attack_scenario_by_model_PROTO.csv')
            self.assertEqual(int(by[(by.scenario=='A')&(by.model=='LightGBM')].iloc[0].detected_positive_windows),1)

    def test_original_stack_reconciliation_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);base,w=self.make_files(root)
            p=base/'public_attack_scenario_recall_PROTO.csv'
            frame=pd.read_csv(p);frame.loc[0,'detected_positive_windows']=1;frame.to_csv(p,index=False)
            with self.assertRaisesRegex(ValueError,'mismatch'):
                run(base,root/'output')

    def test_weighted_misalignment_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);base,w=self.make_files(root)
            p=w/'weighted_public_test_predictions_PROTO.csv'
            frame=pd.read_csv(p);frame.loc[0,'label_binary']=0;frame.to_csv(p,index=False)
            with self.assertRaisesRegex(ValueError,'label mismatch'):
                run(base,root/'output',w)

    def test_score_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);base,w=self.make_files(root)
            p=w/'weighted_public_test_predictions_PROTO.csv'
            frame=pd.read_csv(p);frame.loc[0,'stacked_malicious_score']=.9;frame.to_csv(p,index=False)
            with self.assertRaisesRegex(ValueError,'disagreement'):
                run(base,root/'output',w)


if __name__=='__main__':unittest.main()
