import sys
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from diagnose_pp1_public_stacking_PROTO import diagnose, OOF_KEYS, PRED_KEYS


def test_readonly_diagnostic():
    with tempfile.TemporaryDirectory() as d:
        root=Path(d)
        inp=root/'trained'; inp.mkdir()
        y=np.array([0,0,0,0,1,1,0,0,1,0])
        x=np.array([
          [.05,.10,.08,.02], [.03,.2,.05,.02], [.10,.2,.12,.02],
          [.12,.35,.11,.09], [.7,.83,.67,.35], [.8,.91,.81,.28],
          [.15,.23,.09,.05], [.08,.27,.05,.07], [.55,.78,.61,.15], [.21,.45,.15,.05],
        ])
        meta=LogisticRegression().fit(x,y)
        tr=pd.DataFrame(x,columns=OOF_KEYS)
        tr['label_binary']=y
        tr['oof_group']=[f'g{i}' for i in range(10)]
        tr.to_csv(inp/'public_oof_meta_training_PROTO.csv',index=False)
        te=pd.DataFrame(x,columns=PRED_KEYS)
        te['label_binary']=y
        te['session_id']=[f's{i}' for i in range(10)]
        te['window_start']='2026-01-01T00:00:00Z'
        te['positive_event_count']=y
        te['publisher_attack_scenarios']=np.where(y==1,'Attack A','')
        te['stacked_malicious_score']=meta.predict_proba(x)[:,1]
        te.to_csv(inp/'public_test_predictions_PROTO.csv',index=False)
        joblib.dump({'meta':meta},inp/'tree_models_and_meta_PROTO.joblib')
        out=root/'report'
        rpt=diagnose(inp,out)
        assert rpt['test_positive_windows']==3
        assert rpt['meta']['max_saved_probability_disagreement'] < 1e-8
        assert (out/'public_attack_window_scores_PROTO.csv').exists()
        assert (out/'public_stacking_diagnostic_PROTO.json').exists()


if __name__=='__main__':
    test_readonly_diagnostic()
    print('Local stacking-diagnostic fixture passed')
