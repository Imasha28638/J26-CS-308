import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from fit_pp1_weighted_stacking_PROTO import run, OOF_KEYS, TEST_KEYS


def make_fixture(root):
    d=root/'existing';d.mkdir()
    rng=np.random.default_rng(4010)
    n=195
    y=np.zeros(n,dtype=int)
    # Six independent positive groups, ensures every validation fold could contain positives.
    for i in [0,1,2,3,4,5,6,7,8,9,10,11,12]: y[i]=1
    g=np.array([f'g{i//4}' for i in range(n)],dtype=object)
    # spread positive labels to exactly 6 groups
    g[:13]=['pos0']*3+['pos1']*2+['pos2']*2+['pos3']*2+['pos4']*2+['pos5']*2
    x=np.stack([rng.uniform(.01,.15,n) for _ in range(4)],axis=1)
    x[y==1,:3]+=rng.uniform(.4,.7,size=(sum(y),3))
    x=np.clip(x,0,1)
    tr=pd.DataFrame(x,columns=OOF_KEYS)
    tr['label_binary']=y
    tr['session_id']=[f'train_{i}' for i in range(n)]
    tr['window_start']='2026-01-01T00:00:00Z'
    tr['oof_group']=g
    tr.to_csv(d/'public_oof_meta_training_PROTO.csv',index=False)
    nt=65; yt=np.zeros(nt,dtype=int); yt[:10]=1
    xt=np.stack([rng.uniform(.01,.15,nt) for _ in range(4)],axis=1)
    xt[yt==1,:3]+=rng.uniform(.4,.7,size=(sum(yt),3))
    xt=np.clip(xt,0,1)
    base=LogisticRegression(C=.7,max_iter=3000,random_state=4010).fit(x,y)
    te=pd.DataFrame(xt,columns=TEST_KEYS)
    te['label_binary']=yt
    te['session_id']=[f'test_{i}' for i in range(nt)]
    te['window_start']='2026-02-01T00:00:00Z'
    te['publisher_attack_scenarios']=['attack_1' if value else '' for value in yt]
    te['stacked_malicious_score']=base.predict_proba(xt)[:,1]
    te.to_csv(d/'public_test_predictions_PROTO.csv',index=False)
    joblib.dump({'models':{'Random Forest':'placeholder'},'meta':base,'features':['feature1']},d/'tree_models_and_meta_PROTO.joblib')
    (d/'lstm_PROTO.pt').write_bytes(b'fixture-only')
    (d/'feature_whitelist.json').write_text('{"numeric_features":["feature1"]}')
    (d/'public_experiment_report_PROTO.json').write_text(json.dumps({'scenarios_seen_in_training':['attack_1']}))
    (d/'public_split_audit_PROTO.json').write_text(json.dumps({
      'event_id_overlap':0,'overlap_policy':'drop-train','removed_training_windows':2,
      'original_overlapping_actor_time_windows':2,'train_positive_windows_used':int(y.sum()),
      'test_positive_windows':int(yt.sum()),'train_windows_used':n,'test_windows':nt}))
    return d


def test_complete():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);inp=make_fixture(root);out=root/'candidate'
        result=run(inp,out)
        assert result['candidate'].startswith('LogisticRegression')
        assert result['test_metrics']['Weighted stacking candidate']['tp'] >= 0
        assert (out/'weighted_attack_scenario_recall_PROTO.csv').exists()
        assert (out/'meta_candidate_protocol_PROTO.json').exists()
        assert (out/'lstm_PROTO.pt').read_bytes()==b'fixture-only'
        checkpoint=joblib.load(out/'tree_models_and_meta_PROTO.joblib')
        assert checkpoint['meta'].class_weight=='balanced'
        assert joblib.load(inp/'tree_models_and_meta_PROTO.joblib')['meta'].class_weight is None
        candidate_data=pd.read_csv(out/'weighted_public_test_predictions_PROTO.csv')
        assert len(candidate_data)==65


def test_refuse_inconsistent_baseline():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);inp=make_fixture(root)
        testpath=inp/'public_test_predictions_PROTO.csv'
        data=pd.read_csv(testpath)
        data.loc[0,'stacked_malicious_score']=0.0
        data.to_csv(testpath,index=False)
        try: run(inp,root/'candidate')
        except ValueError as exc: assert 'disagree' in str(exc)
        else: raise AssertionError('Tampered baseline score should fail')


def test_refuse_same_output():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);inp=make_fixture(root)
        try: run(inp,inp)
        except ValueError as exc: assert 'separate' in str(exc)
        else: raise AssertionError('Output path should be different')


if __name__=='__main__':
    test_complete();test_refuse_inconsistent_baseline();test_refuse_same_output()
    print('3 weighted-meta candidate checks passed')
