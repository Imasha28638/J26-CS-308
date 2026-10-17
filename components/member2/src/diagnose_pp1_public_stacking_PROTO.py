#!/usr/bin/env python3
"""Read-only audit of PP1 public CloudTrail stacking model and saved predictions.

Computes diagnostic metrics on the publisher test set, but DOES NOT select
thresholds, refit a model, or use test labels for training decisions.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, roc_auc_score,
                             confusion_matrix, precision_recall_fscore_support)

NAMES = ['Random Forest','LightGBM','XGBoost','LSTM']
PRED_KEYS = ['prob_Random_Forest','prob_LightGBM','prob_XGBoost','prob_LSTM']
OOF_KEYS = ['oof_Random_Forest','oof_LightGBM','oof_XGBoost','oof_LSTM']
STACK_KEY = 'stacked_malicious_score'


def stats(a):
    a = np.asarray(a, dtype=float)
    if not len(a):
        return None
    return {k: round(float(v), 8) for k, v in {
        'min': np.min(a), 'median': np.median(a), 'p90': np.quantile(a, .90),
        'p99': np.quantile(a, .99), 'max': np.max(a), 'mean': np.mean(a),
    }.items()}


def metric(y, scores):
    pred = (np.asarray(scores) >= .5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0,1]).ravel().tolist()
    p,r,f,_ = precision_recall_fscore_support(y,pred,average='binary',zero_division=0)
    return dict(precision=round(float(p),6),recall=round(float(r),6),f1=round(float(f),6),
                tp=int(tp), fp=int(fp), fn=int(fn), tn=int(tn), predicted_positive=int(pred.sum()),
                average_precision=round(float(average_precision_score(y,scores)),6),
                roc_auc=round(float(roc_auc_score(y,scores)),6),
                overall_score_summary=stats(scores),
                positive_window_scores=stats(np.asarray(scores)[np.asarray(y)==1]),
                negative_window_scores=stats(np.asarray(scores)[np.asarray(y)==0]))


def diagnose(model_dir: Path, output_dir: Path):
    p_test = model_dir/'public_test_predictions_PROTO.csv'
    p_oof = model_dir/'public_oof_meta_training_PROTO.csv'
    p_model = model_dir/'tree_models_and_meta_PROTO.joblib'
    for p in (p_test,p_oof,p_model):
        if not p.is_file(): raise FileNotFoundError(str(p))
    te = pd.read_csv(p_test, encoding='utf-8-sig')
    tr = pd.read_csv(p_oof, encoding='utf-8-sig')
    missing_test = (set(PRED_KEYS + [STACK_KEY,'label_binary'])-set(te.columns))
    missing_oof = (set(OOF_KEYS+['label_binary','oof_group'])-set(tr.columns))
    if missing_test or missing_oof:
        raise ValueError(f'Missing prediction columns: test={sorted(missing_test)}, oof={sorted(missing_oof)}')
    if not set(te.label_binary.unique()).issubset({0,1}) or not set(tr.label_binary.unique()).issubset({0,1}):
        raise ValueError('Unexpected class labels')
    if len(set(te.label_binary))!=2 or len(set(tr.label_binary))!=2:
        raise ValueError('Both classes required in train and test')
    for col in PRED_KEYS+[STACK_KEY]:
        a=te[col].to_numpy(dtype=float)
        if not np.isfinite(a).all() or (a < 0).any() or (a > 1).any():
            raise ValueError(f'Invalid test probabilities in {col}')
    for col in OOF_KEYS:
        a=tr[col].to_numpy(dtype=float)
        if not np.isfinite(a).all() or (a < 0).any() or (a > 1).any():
            raise ValueError(f'Invalid OOF probabilities in {col}')
    # Only load checkpoint created locally by the research student; joblib relies on pickle.
    saved = joblib.load(p_model)
    meta = saved.get('meta')
    if meta is None or not hasattr(meta, 'coef_'):
        raise ValueError('Missing fitted logistic regression meta-learner')
    coefs = np.asarray(meta.coef_)[0]
    if len(coefs)!=4: raise ValueError('Expected 4 meta features')
    recomputed = meta.predict_proba(te[PRED_KEYS].to_numpy(dtype=float))[:,1]
    max_diff = float(np.abs(recomputed-te[STACK_KEY].to_numpy(dtype=float)).max())
    if max_diff > 1e-6:
        raise ValueError(f'Saved stacking probabilities disagree with checkpoint, max difference={max_diff}')
    yte=te.label_binary.to_numpy(dtype=int)
    ytr=tr.label_binary.to_numpy(dtype=int)
    test_metrics={name:metric(yte,te[key].to_numpy(dtype=float)) for name,key in zip(NAMES,PRED_KEYS)}
    test_metrics['Stacking ensemble']=metric(yte,te[STACK_KEY].to_numpy(dtype=float))
    trained_meta_oof_scores=meta.predict_proba(tr[OOF_KEYS].to_numpy(dtype=float))[:,1]
    # These scores are IN-SAMPLE w.r.t. the trained meta-learner; descriptive only.
    groups = tr[['oof_group','label_binary']].groupby('oof_group').label_binary.max()
    positives_by_group=tr.loc[tr.label_binary==1].groupby('oof_group').size().sort_values(ascending=False)
    top=te.sort_values(STACK_KEY,ascending=False).head(25).copy()
    keep=['session_id','window_start','label_binary','positive_event_count',
          'publisher_attack_scenarios'] + PRED_KEYS + [STACK_KEY]
    keep=[c for c in keep if c in top.columns]
    output_dir.mkdir(parents=True,exist_ok=True)
    top[keep].to_csv(output_dir/'public_top_stacking_scores_PROTO.csv',index=False,encoding='utf-8-sig')
    top_positives=te.loc[te.label_binary==1].sort_values(STACK_KEY,ascending=False)
    top_positives[keep].to_csv(output_dir/'public_attack_window_scores_PROTO.csv',index=False,encoding='utf-8-sig')
    report={
      'study':'Diagnostic of saved PP1 public CloudTrail stacking checkpoint (read-only)',
      'test_windows':len(te),'test_positive_windows':int(yte.sum()),
      'training_oof_windows':len(tr),'training_oof_positive_windows':int(ytr.sum()),
      'positive_oof_group_count':int((groups==1).sum()),
      'positive_windows_per_group':{str(k):int(v) for k,v in positives_by_group.items()},
      'meta':{'type':type(meta).__name__,'intercept':float(meta.intercept_[0]),
              'coefficients_by_base_model':{k:float(v) for k,v in zip(NAMES,coefs)},
              'class_weight':str(meta.class_weight),
              'train_oof_meta_score_summary_in_sample_descriptive_only':stats(trained_meta_oof_scores),
              'train_oof_meta_positive_scores_in_sample_descriptive_only':stats(trained_meta_oof_scores[ytr==1]),
              'train_oof_meta_predicted_positive_at_0_5_in_sample_descriptive_only':int((trained_meta_oof_scores>=.5).sum()),
              'max_saved_probability_disagreement':max_diff},
      'test_metrics_fixed_threshold_0_5':test_metrics,
      'interpretation_note':'This is a post-training audit. Never select a threshold or hyperparameter using publisher TestOn. OOF training scores from the fitted meta model are in-sample for that meta model; new candidate thresholds require group-separated meta-level validation on TrainOn only.',
    }
    (output_dir/'public_stacking_diagnostic_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 public CloudTrail stacking diagnosis completed')
    print(f'  Training OOF positives: {int(ytr.sum())}/{len(tr)}, across {(groups==1).sum()} groups')
    print(f'  Test positive windows: {int(yte.sum())}/{len(te)}')
    print(f'  Meta intercept: {meta.intercept_[0]:.6f}; class_weight={meta.class_weight}')
    print('  Meta coefficients: '+', '.join(f'{n}={c:+.5f}' for n,c in zip(NAMES,coefs)))
    for name in ('LightGBM','Stacking ensemble'):
        m=test_metrics[name]
        print(f'  {name}: TP={m["tp"]}, FP={m["fp"]}, FN={m["fn"]}, TN={m["tn"]}, AP={m["average_precision"]:.3f}, ROC-AUC={m["roc_auc"]:.3f}')
        print(f'    Test score max={m["overall_score_summary"]["max"]:.6f}; positive-window median={m["positive_window_scores"]["median"]:.6f}')
    if not test_metrics['Stacking ensemble']['predicted_positive']:
        print('  DIAGNOSTIC: Stacking produced no positive predictions at threshold 0.5.')
    print('  No training, model updates, or threshold selection performed.')
    print('  Report: '+str(output_dir/'public_stacking_diagnostic_PROTO.json'))
    return report


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--models-dir',type=Path,default=Path('Data/Experiments/pp1_public_cloudtrail_PROTO'))
    a.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_public_stacking_diagnostic_PROTO'))
    args=a.parse_args()
    diagnose(args.models_dir,args.output_dir)

if __name__=='__main__':main()
