#!/usr/bin/env python3
"""Test how well collection-origin metadata alone predicts PP1 mixed-source labels.

Model-origin baseline is diagnostic, not a deployable model. No trained artifacts
are altered. Train/test rows are recovered by unique session/window keys.
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score,recall_score,f1_score,accuracy_score,confusion_matrix


def audit(features_path,preds_path,out_dir):
    data=pd.read_csv(features_path,dtype={'session_id':str,'window_start':str},encoding='utf-8-sig')
    test=pd.read_csv(preds_path,dtype={'session_id':str,'window_start':str},encoding='utf-8-sig')
    key=['session_id','window_start']
    feature_required={'data_origin','label_binary',*key}
    test_required={'label_binary','stacked_malicious_score',*key}
    if not feature_required.issubset(data) or not test_required.issubset(test):
        raise ValueError('Missing required columns in features or test predictions')
    if data.duplicated(key).any() or test.duplicated(key).any():
        raise ValueError('Duplicate (session_id, window_start) pairs detected')
    merged=data.merge(test[key+['label_binary']],how='left',on=key,indicator=True,suffixes=('_all','_test'),validate='one_to_one')
    te=merged['_merge']=='both'
    train=merged.loc[~te].copy()
    test_rows=merged.loc[te].copy()
    if (test_rows['label_binary_all']!=test_rows['label_binary_test']).any():
        raise ValueError('Test labels do not reconcile with feature table')
    if train.empty or test_rows.empty:
        raise ValueError('Train/test separation failed')
    if set(train.session_id) & set(test_rows.session_id):
        raise ValueError('Train and test share session IDs')
    # Leakage-diagnostic model: smoothed P(positive|source), learned on train only.
    stats=train.groupby('data_origin').label_binary_all.agg(['count','sum']).reset_index()
    stats['smoothed_attack_rate']=(stats['sum']+1)/(stats['count']+2)
    prior=float((train.label_binary_all.sum()+1)/(len(train)+2))
    probabilities=dict(zip(stats.data_origin,stats.smoothed_attack_rate))
    prob=np.asarray([probabilities.get(origin,prior) for origin in test_rows.data_origin],dtype=float)
    pred=(prob>=.5).astype(int)
    y=test_rows.label_binary_all.to_numpy(dtype=int)
    cm=confusion_matrix(y,pred,labels=[0,1]).tolist()
    stack_column='stacked_malicious_score'
    if stack_column not in test.columns:
        raise ValueError('Test predictions missing stacking score')
    prob_stack=test.set_index(key)[stack_column]
    stack_scores=np.asarray([float(prob_stack.loc[(r.session_id,r.window_start)]) for r in test_rows.itertuples()],dtype=float)
    def metrics(prob_values):
        binary=prob_values>=.5
        return dict(accuracy=float(accuracy_score(y,binary)),precision=float(precision_score(y,binary,zero_division=0)),
                    recall=float(recall_score(y,binary,zero_division=0)),f1=float(f1_score(y,binary,zero_division=0)),
                    confusion_matrix_0_1=confusion_matrix(y,binary,labels=[0,1]).tolist())
    by_origin=data.groupby(['data_origin','label_binary']).size().unstack(fill_value=0)
    out=Path(out_dir);out.mkdir(parents=True,exist_ok=True)
    by_origin.to_csv(out/'label_by_collection_origin_PROTO.csv',encoding='utf-8-sig')
    comparison=test_rows[key+['data_origin','label_binary_all']].copy()
    comparison.rename(columns={'label_binary_all':'label_binary'},inplace=True)
    comparison['origin_only_score']=prob
    comparison['origin_only_predicted_binary']=pred
    comparison['stacked_malicious_score']=stack_scores
    comparison.to_csv(out/'origin_baseline_test_predictions_PROTO.csv',index=False,encoding='utf-8-sig')
    result={
        'purpose':'PP1 diagnosis of possible label-source confounding',
        'train_windows':len(train),'test_windows':len(test_rows),
        'train_sessions':train.session_id.nunique(),'test_sessions':test_rows.session_id.nunique(),
        'source_only_baseline':metrics(prob),'stacking_ensemble':metrics(stack_scores),
        'smoothed_attack_rate_by_origin_training':{str(k):float(v) for k,v in probabilities.items()},
        'interpretation':('Origin-only performance indicates how predictable labels are from dataset provenance, '
                          'even when provenance was excluded from the final model feature list. '
                          'This is a diagnostic, not proof of causal leakage.'),
        'warnings':[
            'This diagnostic uses collection source, a deliberately excluded model input.',
            'Training labels are scenario-associated and generated-intent labels, not uniformly verified AWS ground truth.',
            'Even group-separated splits do not remove data origin and behavioral distribution confounding.',
        ],
    }
    (out/'source_bias_report_PROTO.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('PP1 collection-origin bias check completed')
    print('  Test windows:',len(test_rows),'| Train sessions:',train.session_id.nunique(),'| Test sessions:',test_rows.session_id.nunique())
    print(f'  Origin-only F1: {result["source_only_baseline"]["f1"]:.3f}')
    print(f'  Stacking F1:     {result["stacking_ensemble"]["f1"]:.3f}')
    print('  This check does not alter saved models or test predictions')
    print('Output:',out)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--features',type=Path,default=Path('Data/Experiments/pp1_mixed_PROTO/window_features_PROTO.csv'))
    p.add_argument('--test-predictions',type=Path,default=Path('Data/Experiments/pp1_mixed_PROTO/test_predictions_PROTO.csv'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_source_bias_PROTO'))
    a=p.parse_args()
    try: audit(a.features,a.test_predictions,a.output_dir)
    except (ValueError,KeyError,FileNotFoundError) as e:p.exit(2,f'ERROR: {e}\n')

if __name__=='__main__': main()
