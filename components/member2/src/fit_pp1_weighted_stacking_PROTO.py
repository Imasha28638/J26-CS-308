#!/usr/bin/env python3
"""Fixed-protocol, training-only class-weighted stacked meta-learner for PP1 CloudTrail.

Uses previously saved TrainOn OOF base scores for fitting and group-CV, and
saved TestOn base scores for one final evaluation. No base models are retrained.
The candidate C, class weighting and threshold are fixed in source code,
never selected with TestOn labels. Baseline artifacts remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import StratifiedGroupKFold

NAMES = ['Random Forest', 'LightGBM', 'XGBoost', 'LSTM']
OOF_KEYS = ['oof_Random_Forest', 'oof_LightGBM', 'oof_XGBoost', 'oof_LSTM']
TEST_KEYS = ['prob_Random_Forest', 'prob_LightGBM', 'prob_XGBoost', 'prob_LSTM']
C_FIXED = 0.7
THRESHOLD_FIXED = 0.5
SEED_FIXED = 4010
FOLDS_FIXED = 3


def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()


def validate_frame(df, columns, kind):
    required=set(columns)|{'label_binary','session_id','window_start'}
    if kind == 'train': required.add('oof_group')
    missing=required-set(df.columns)
    if missing: raise ValueError(f'{kind}: missing fields: {sorted(missing)}')
    if df.empty or df[list(required)].isna().any().any():
        raise ValueError(f'{kind}: empty file or required null values')
    if not set(df.label_binary.unique()).issubset({0,1}) or len(df.label_binary.unique())!=2:
        raise ValueError(f'{kind}: expected binary labels 0 and 1')
    values=df[columns].to_numpy(dtype=float)
    if not np.isfinite(values).all() or (values<0).any() or (values>1).any():
        raise ValueError(f'{kind}: probabilities outside [0,1]')
    if df[['session_id','window_start']].duplicated().any():
        raise ValueError(f'{kind}: repeated actor/window keys')
    return values


def candidate():
    return LogisticRegression(C=C_FIXED, max_iter=3000,
                              class_weight='balanced', random_state=SEED_FIXED)


def measure(labels, scores, threshold=THRESHOLD_FIXED):
    labels=np.asarray(labels,dtype=int)
    scores=np.asarray(scores,dtype=float)
    pred=(scores>=threshold).astype(int)
    tn,fp,fn,tp=confusion_matrix(labels,pred,labels=[0,1]).ravel()
    p,r,f,_=precision_recall_fscore_support(labels,pred,average='binary',zero_division=0)
    result={'precision':float(p),'recall':float(r),'f1':float(f),
            'tp':int(tp),'fp':int(fp),'fn':int(fn),'tn':int(tn),
            'predicted_positive':int(pred.sum()),'score_min':float(scores.min()),
            'score_median':float(np.median(scores)),'score_max':float(scores.max())}
    if len(set(labels))==2:
        result['average_precision']=float(average_precision_score(labels,scores))
        result['roc_auc']=float(roc_auc_score(labels,scores))
    return result


def meta_cv(x,y,groups):
    # Group CV is a diagnostic using training OOF base scores. Because the
    # first-level OOF features are not generated in outer nested CV folds,
    # these CV scores must NOT be presented as independent generalization.
    groups=np.asarray(groups,dtype=str)
    if len(set(groups[y==1]))<FOLDS_FIXED or len(set(groups[y==0]))<FOLDS_FIXED:
        raise ValueError('Too few positive/negative OOF groups for three-fold meta CV')
    found=None
    for offset in range(60):
        skf=StratifiedGroupKFold(n_splits=FOLDS_FIXED, shuffle=True,
                                random_state=SEED_FIXED+offset)
        plans=list(skf.split(x,y,groups))
        if all(len(set(y[tr]))==2 and len(set(y[va]))==2 and
               not (set(groups[tr])&set(groups[va])) for tr,va in plans):
            found=(plans,SEED_FIXED+offset)
            break
    if found is None:
        raise ValueError('Cannot form 3 group-separated meta folds containing both classes')
    plans,seed=found
    fold_rows=[]
    for i,(train_i,val_i) in enumerate(plans,1):
        model=candidate().fit(x[train_i],y[train_i])
        scores=model.predict_proba(x[val_i])[:,1]
        fold_rows.append({'fold':i,'training_windows':len(train_i),
                          'validation_windows':len(val_i),
                          'training_positives':int(y[train_i].sum()),
                          'validation_positives':int(y[val_i].sum()),
                          'training_groups':len(set(groups[train_i])),
                          'validation_groups':len(set(groups[val_i])),
                          **measure(y[val_i],scores)})
    return {'fold_seed':seed,'folds':fold_rows,
            'note':'Training-OOF group-CV diagnostic only; not fully nested base-model evaluation.'}


def scenario_rows(test, scores, seen):
    if 'publisher_attack_scenarios' not in test.columns:
        return []
    names=sorted({part.strip() for value in test.publisher_attack_scenarios.fillna('').astype(str)
                  for part in value.split('|') if part.strip()})
    out=[]
    for name in names:
        mask=test.publisher_attack_scenarios.fillna('').astype(str).map(
            lambda v: name in {p.strip() for p in v.split('|')})
        if not mask.any(): continue
        sub=np.asarray(scores)[mask.to_numpy()]
        detected=int((sub>=THRESHOLD_FIXED).sum())
        out.append({'scenario':name,'seen_in_training':name in seen,
                    'positive_test_windows':len(sub),'detected_positive_windows':detected,
                    'window_recall':detected/len(sub)})
    return out


def run(models_dir:Path,output_dir:Path):
    models_dir=models_dir.resolve()
    output_dir=output_dir.resolve()
    if models_dir == output_dir or models_dir in output_dir.parents:
        raise ValueError('Output must be a separate directory outside baseline model tree; baseline is read-only')
    files={
      'oof':models_dir/'public_oof_meta_training_PROTO.csv',
      'test':models_dir/'public_test_predictions_PROTO.csv',
      'model':models_dir/'tree_models_and_meta_PROTO.joblib',
      'audit':models_dir/'public_split_audit_PROTO.json',
      'report':models_dir/'public_experiment_report_PROTO.json',
      'lstm':models_dir/'lstm_PROTO.pt',
      'whitelist':models_dir/'feature_whitelist.json',
    }
    for name,p in files.items():
        if not p.is_file(): raise FileNotFoundError(f'{name}: {p}')
    audit=json.loads(files['audit'].read_text(encoding='utf-8'))
    if audit.get('event_id_overlap')!=0 or audit.get('overlap_policy')!='drop-train' or \
       audit.get('removed_training_windows',0)<audit.get('original_overlapping_actor_time_windows',0):
        raise ValueError('Baseline split audit must confirm no ID overlap and dropping shared actor/time windows')
    original_report=json.loads(files['report'].read_text(encoding='utf-8'))
    tr=pd.read_csv(files['oof'],encoding='utf-8-sig')
    te=pd.read_csv(files['test'],encoding='utf-8-sig')
    x=validate_frame(tr,OOF_KEYS,'train')
    xt=validate_frame(te,TEST_KEYS,'test')
    if set(zip(tr.session_id,tr.window_start))&set(zip(te.session_id,te.window_start)):
        raise ValueError('Train/test actor-window overlap in saved prediction files')
    y=tr.label_binary.to_numpy(dtype=int)
    yt=te.label_binary.to_numpy(dtype=int)
    if int(y.sum())!=audit['train_positive_windows_used'] or int(yt.sum())!=audit['test_positive_windows']:
        raise ValueError('Saved prediction label counts differ from split audit')
    if len(tr)!=audit['train_windows_used'] or len(te)!=audit['test_windows']:
        raise ValueError('Saved prediction row counts differ from split audit')
    original=joblib.load(files['model']) # only trust locally trained files
    if not {'models','meta','features'}.issubset(original):
        raise ValueError('Missing baseline model bundle keys')
    predicted=original['meta'].predict_proba(xt)[:,1]
    saved=te['stacked_malicious_score'].to_numpy(dtype=float)
    if np.max(abs(predicted-saved))>1e-6:
        raise ValueError('Saved test scores disagree with baseline model checkpoint')
    # All choices were fixed before test labels are read for evaluation.
    cv=meta_cv(x,y,tr.oof_group.to_numpy(dtype=str))
    fitted=candidate().fit(x,y)
    candidate_scores=fitted.predict_proba(xt)[:,1]
    output_dir.mkdir(parents=True,exist_ok=True)
    bundle={'models':original['models'],'meta':fitted,'features':original['features'],
            'meta_protocol':{'name':'class_weight_balanced_fixed_C_0.7',
                             'threshold':THRESHOLD_FIXED,
                             'candidate_selection':'fixed in advance; train OOF only'}}
    joblib.dump(bundle,output_dir/'tree_models_and_meta_PROTO.joblib')
    for src,dest in [('lstm','lstm_PROTO.pt'),('whitelist','feature_whitelist.json')]:
        shutil.copy2(files[src],output_dir/dest)
    freeze={'protocol':'Weighted stacking candidate; fixed parameters and fixed threshold',
            'class_weight':'balanced','C':C_FIXED,'threshold':THRESHOLD_FIXED,'seed':SEED_FIXED,
            'fit_rows':len(tr),'fit_positives':int(y.sum()),
            'train_positive_groups':len(set(tr.oof_group[y==1])),
            'input_sha256':{k:sha256(files[k]) for k in ('oof','test','model','audit','report')},
            'no_publisher_test_based_model_selection':True}
    (output_dir/'meta_candidate_protocol_PROTO.json').write_text(json.dumps(freeze,indent=2),encoding='utf-8')
    (output_dir/'meta_training_group_cv_PROTO.json').write_text(json.dumps(cv,indent=2),encoding='utf-8')
    # Final evaluation: only now use publisher test labels.
    metrics={
      'LightGBM':measure(yt,te['prob_LightGBM'].to_numpy(dtype=float)),
      'Previous stacking':measure(yt,saved),
      'Weighted stacking candidate':measure(yt,candidate_scores),
    }
    pred=te.copy()
    pred['candidate_stacking_score']=candidate_scores
    pred['candidate_predicted_binary']=(candidate_scores>=THRESHOLD_FIXED).astype(int)
    pred.to_csv(output_dir/'weighted_public_test_predictions_PROTO.csv',index=False,encoding='utf-8-sig')
    seen=set(original_report.get('scenarios_seen_in_training',[]))
    scenarios=scenario_rows(te,candidate_scores,seen)
    pd.DataFrame(scenarios,columns=['scenario','seen_in_training','positive_test_windows',
             'detected_positive_windows','window_recall']).to_csv(
              output_dir/'weighted_attack_scenario_recall_PROTO.csv',index=False,encoding='utf-8-sig')
    report={'experiment':'PP1 public CloudTrail balanced meta-learner comparison',
            'candidate':'LogisticRegression class_weight=balanced, C=0.7, threshold=0.5',
            'meta_coefficients':{name:float(v) for name,v in zip(NAMES,fitted.coef_[0])},
            'meta_intercept':float(fitted.intercept_[0]),
            'train_windows':len(tr),'train_positive_windows':int(y.sum()),
            'test_windows':len(te),'test_positive_windows':int(yt.sum()),
            'test_metrics':metrics,'per_scenario_candidate':scenarios,
            'important_limitations':[
              'Class-weighted scores are not automatically calibrated probabilities.',
              'Only a few independent positive actor-day training groups are available.',
              'The meta-level group CV is not fully nested base-model validation.',
              'The publisher split shares actor identities even after actor/time-window overlap removal.',
              'The publisher test set was examined in the previous baseline diagnosis; any future choices influenced by those results are exploratory.',
              'This candidate uses a fixed protocol; test labels were not used to choose its parameters or threshold.',
            ]}
    (output_dir/'weighted_meta_experiment_report_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 public CloudTrail class-weighted stacking candidate completed')
    print(f'  Meta training windows: {len(tr)}; attack-containing: {int(y.sum())}; positive actor-day groups: {len(set(tr.oof_group[y==1]))}')
    print(f'  Candidate: logistic regression C={C_FIXED}, class_weight=balanced, fixed threshold={THRESHOLD_FIXED}')
    for label,item in metrics.items():
        print(f"  {label:27s} F1={item['f1']:.3f} Precision={item['precision']:.3f} Recall={item['recall']:.3f} TP={item['tp']} FP={item['fp']}")
    print(f'  Candidate score max={metrics["Weighted stacking candidate"]["score_max"]:.5f}')
    for row in cv['folds']:
        print(f"  Training-group CV fold {row['fold']}: F1={row['f1']:.3f}, P={row['precision']:.3f}, R={row['recall']:.3f}, positives={row['validation_positives']}")
    print('  Publisher TestOn used for final comparison only, not candidate fitting or threshold selection')
    print('  Output:',output_dir)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--models-dir',type=Path,default=Path('Data/Experiments/pp1_public_cloudtrail_PROTO'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_public_weighted_meta_PROTO'))
    args=p.parse_args()
    run(args.models_dir,args.output_dir)

if __name__=='__main__':
    main()
