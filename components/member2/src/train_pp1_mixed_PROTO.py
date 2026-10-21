#!/usr/bin/env python3
"""Train a mixed-source PP1 prototype, preserving all source/label caveats.

Uses collected Splunk attack-scenario candidates, generated normal operations,
and an external positive-only Stratus approved-attack recall check.
Imports feature engineering and model definitions from original working trainer.
"""
import argparse
import json
import random
from collections import defaultdict, Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

from train_pp1_binary_stack import (
    FEATURES, MAX_SEQ, SEQ_DIM, floor_t, featureize_group, pad_sequences,
    construct_models, train_lstm, lstm_predict, evaluate,
)


def read_csv(path):
    return pd.read_csv(path,dtype=str,keep_default_na=False,encoding='utf-8-sig').to_dict('records')


def make_windows(rows,window_minutes=5):
    required={'session_id','event_id','event_time','event_name','event_source',
              'read_only','error_code','aws_region','observed_positive_flag','data_origin'}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f'Input missing required event fields: {sorted(required-set(rows[0])) if rows else "no rows"}')
    collection=defaultdict(list)
    for r in rows:
        if r.get('observed_positive_flag') not in ('0','1',''):
            raise ValueError('Invalid attack evidence flag')
        collection[(r['session_id'],floor_t(r['event_time'],window_minutes))].append(r)
    records=[];sequences=[]
    for (sid,dt),sample in sorted(collection.items()):
        feat,seq=featureize_group(sample,window_minutes)
        labels=set(r['observed_positive_flag'] for r in sample)
        label=1 if '1' in labels else 0 if '0' in labels else None
        classes={r['candidate_attack_class'] for r in sample if r['observed_positive_flag']=='1' and r['candidate_attack_class']}
        records.append({'session_id':sid,'window_start':dt.strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'label_binary':label,'attack_class':next(iter(classes)) if len(classes)==1 else '',
                        'data_origin':sample[0]['data_origin'], **feat})
        sequences.append(seq)
    return pd.DataFrame(records),sequences


def grouped_folds(groups,y,n_folds=3,seed=4010):
    """Each fold has disjoint positive scenario groups and benign session groups."""
    uniq=sorted(set(groups)); labels={}
    sizes=Counter(groups)
    for g in uniq:
        g_y=set(y[groups==g]);
        labels[g]=int(max(g_y))
    rng=random.Random(seed)
    group_assign={};fold_counts=[[0,0] for _ in range(n_folds)]
    for label in (1,0):
        subset=[g for g in uniq if labels[g]==label]
        if len(subset)<n_folds:raise ValueError('Insufficient independent scenario groups for out-of-fold training')
        rng.shuffle(subset)
        subset.sort(key=lambda g:-sizes[g])
        for g in subset:
            fold=min(range(n_folds),key=lambda f:(fold_counts[f][label],len([x for x in group_assign.values() if x==f])))
            group_assign[g]=fold; fold_counts[fold][label]+=sizes[g]
    for i in range(n_folds):
        val=np.asarray([j for j,g in enumerate(groups) if group_assign[g]==i],dtype=int)
        trn=np.asarray([j for j,g in enumerate(groups) if group_assign[g]!=i],dtype=int)
        if not len(val) or not len(trn) or len(set(y[trn]))!=2 or len(set(y[val]))!=2:
            raise RuntimeError('Unusable group fold')
        assert not set(groups[val]) & set(groups[trn])
        yield trn,val


def save_predictions(df,mask,probs,stacked,name,out):
    d=df.loc[mask,['session_id','window_start','label_binary','attack_class','data_origin']].copy().reset_index(drop=True)
    for i,model in enumerate(name):d['prob_'+model.replace(' ','_')]=probs[:,i]
    d['stacked_malicious_score']=stacked
    d['predicted_binary']=(stacked>=.5).astype(int)
    d.to_csv(out,index=False,encoding='utf-8-sig')
    return d


def run(mixed_path,external_path,out_dir,minutes=5,epochs=4,seed=4010):
    torch.set_num_threads(min(2,max(1,torch.get_num_threads())))
    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed)
    rows=read_csv(mixed_path)
    df,seqs=make_windows(rows,minutes)
    df['label_binary']=df.label_binary.astype(int)
    if not set(df.data_origin)=={'Splunk Attack Data','Generated CloudTrail'}:
        raise ValueError('Training file must contain only the two authorized development sources')
    if not (df.loc[df.data_origin=='Splunk Attack Data','label_binary']==1).all():
        raise ValueError('Splunk attack-scenario inputs must have candidate positive labels')
    group_labels=df.groupby('session_id')['label_binary'].max()
    n_attack_groups=int((group_labels==1).sum())
    n_benign_groups=int((group_labels==0).sum())
    if n_attack_groups<6 or n_benign_groups<10:
        raise ValueError('Too few independent scenario/session groups')
    sessions=group_labels.reset_index()
    train_groups,test_groups=train_test_split(sessions.session_id,test_size=.2,random_state=seed,
                                            stratify=sessions.label_binary)
    tr=df.session_id.isin(set(train_groups)).to_numpy()
    te=~tr
    assert not set(df.session_id[tr]) & set(df.session_id[te])
    x=df[FEATURES].to_numpy(dtype=float);y=df.label_binary.to_numpy(dtype=int)
    seq,lens=pad_sequences(seqs)
    Xtr=X=x[tr];ytr=y[tr];Xte=x[te];yte=y[te]
    Str=seq[tr];Ste=seq[te];Ltr=lens[tr];Lte=lens[te]
    groups=df.session_id[tr].to_numpy()
    names=['Random Forest','LightGBM','XGBoost','LSTM']
    oof=np.zeros((len(Xtr),4),dtype=float);test_probs=np.zeros((len(Xte),4),dtype=float)
    print('PP1 mixed-source training')
    print(f'  Window counts: train={len(Xtr)}, test={len(Xte)}')
    print(f'  Attack-scenario groups: {n_attack_groups}, generated-normal sessions: {n_benign_groups}')
    print(f'  Attack windows: train={int(ytr.sum())}, test={int(yte.sum())}')
    for f,(fit,val) in enumerate(grouped_folds(groups,ytr,n_folds=3,seed=seed),1):
        for j,(name,model) in enumerate(construct_models(seed+f)):
            model.fit(Xtr[fit],ytr[fit]);oof[val,j]=model.predict_proba(Xtr[val])[:,1]
        model=train_lstm(Str[fit],Ltr[fit],ytr[fit],seed+f,epochs)
        oof[val,3]=lstm_predict(model,Str[val],Ltr[val])
        print(f'  Group-separated meta-training fold {f}/3 completed')
    tree={}
    for j,(name,model) in enumerate(construct_models(seed)):
        model.fit(Xtr,ytr);test_probs[:,j]=model.predict_proba(Xte)[:,1];tree[name]=model
    final_lstm=train_lstm(Str,Ltr,ytr,seed,epochs)
    test_probs[:,3]=lstm_predict(final_lstm,Ste,Lte)
    meta=LogisticRegression(C=.7,max_iter=2000,random_state=seed).fit(oof,ytr)
    stacked=meta.predict_proba(test_probs)[:,1]
    scores={name:evaluate(yte,test_probs[:,j]) for j,name in enumerate(names)}
    scores['Stacking ensemble']=evaluate(yte,stacked)
    scores['Hard voting']=evaluate(yte,(test_probs>=.5).sum(axis=1).astype(float)/4.0+1e-10)
    scores['Soft voting']=evaluate(yte,test_probs.mean(axis=1))
    out=Path(out_dir);out.mkdir(parents=True,exist_ok=True)
    save_predictions(df,te,test_probs,stacked,names,out/'test_predictions_PROTO.csv')
    df.loc[tr,['session_id','window_start','label_binary']].assign(**{
        f'oof_{n.replace(" ","_")}':oof[:,i] for i,n in enumerate(names)
    }).to_csv(out/'oof_meta_training_PROTO.csv',index=False,encoding='utf-8-sig')
    df.to_csv(out/'window_features_PROTO.csv',index=False,encoding='utf-8-sig')
    joblib.dump({'models':tree,'meta':meta,'features':FEATURES},out/'tree_models_and_meta_PROTO.joblib')
    torch.save({'state_dict':final_lstm.state_dict(),'sequence_dim':SEQ_DIM,'max_seq':MAX_SEQ},out/'lstm_PROTO.pt')
    (out/'feature_whitelist.json').write_text(json.dumps({'numeric_features':FEATURES},indent=2),encoding='utf-8')
    # External positive-only Stratus check. No negative samples are implied.
    ext_rows=read_csv(external_path)
    ext_df,ext_seqs=make_windows(ext_rows,minutes)
    approved_mask=ext_df.label_binary.notna().to_numpy()
    ext_pos=ext_df.loc[approved_mask].copy()
    if len(ext_pos) and not (ext_pos.label_binary==1).all():
        raise ValueError('Stratus external evidence includes unapproved negative labels')
    ext_features=ext_df[FEATURES].to_numpy(dtype=float)
    exseq,exlens=pad_sequences(ext_seqs)
    extp=np.zeros((len(ext_df),4),dtype=float)
    for j,name in enumerate(names[:3]):extp[:,j]=tree[name].predict_proba(ext_features)[:,1]
    extp[:,3]=lstm_predict(final_lstm,exseq,exlens)
    external_prob=meta.predict_proba(extp)[:,1]
    external_df=ext_df.loc[approved_mask,['session_id','window_start','attack_class','event_count','logging_mutation_count']].copy().reset_index(drop=True)
    external_df['stacked_malicious_score']=external_prob[approved_mask]
    external_df['predicted_binary']=(external_prob[approved_mask]>=.5).astype(int)
    external_df.to_csv(out/'stratus_approved_attack_recall_PROTO.csv',index=False,encoding='utf-8-sig')
    ext_hits=int(external_df.predicted_binary.sum());ext_total=len(external_df)
    report={
        'experiment':'PP1 mixed-source baseline',
        'training_attacks':'Splunk scenario-associated candidates',
        'training_normal':'generated normal operations by design',
        'training_additional_attack':'generated controlled injected attack sequences',
        'test_split':'disjoint scenario/session group 80/20; source class confounding remains a research limitation',
        'model_count':4,'meta_model':'Logistic Regression, group-separated out-of-fold predictions',
        'train_windows':len(Xtr),'test_windows':len(Xte),'test_attack_windows':int(yte.sum()),
        'test_normal_windows':int(len(yte)-yte.sum()),
        'model_metrics':scores,
        'external_stratus_approved_positive_windows':ext_total,
        'external_stratus_detected_positive_windows':ext_hits,
        'external_stratus_positive_recall':ext_hits/ext_total if ext_total else None,
        'interpretation':'Exploratory mixed-source development comparison only',
        'limitations':[
            'Collection source may remain correlated with class; reported classification performance may reflect source differences.',
            'Splunk attack associations are scenario proxies, not validated per-event ground truth.',
            'Normal examples and controlled injected attacks are generated and may not represent real account behaviors.',
            'Stratus external check evaluates recall of attack-containing windows only; no specificity or precision can be estimated.',
            'External Stratus attack contexts are often single-event; LSTM temporal performance cannot be inferred.',
            'This is binary classification only; attack class labels are for analysis, not predicted classes.',
        ],
    }
    (out/'mixed_experiment_report_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('  Held-out scenario-group test results:')
    for name,m in scores.items():print(f"    {name:19s} F1={m['f1']:.3f} Precision={m['precision']:.3f} Recall={m['recall']:.3f}")
    print(f'  External approved Stratus attack-window recall: {ext_hits}/{ext_total}')
    print('  Evaluation scope: mixed-source exploratory; source/label correlation documented in report')
    print('  Output:',out)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mixed-events',type=Path,default=Path('Data/Interim/pp1_mixed_PROTO/mixed_training_events_PROTO.csv'))
    p.add_argument('--stratus-evidence',type=Path,default=Path('Data/Interim/pp1_mixed_PROTO/stratus_external_evidence_PROTO.csv'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_mixed_PROTO'))
    p.add_argument('--window-minutes',type=int,default=5)
    p.add_argument('--lstm-epochs',type=int,default=4)
    p.add_argument('--seed',type=int,default=4010)
    a=p.parse_args()
    if a.window_minutes<1 or 60%a.window_minutes!=0:raise SystemExit('window-minutes must divide 60')
    run(a.mixed_events,a.stratus_evidence,a.output_dir,a.window_minutes,a.lstm_epochs,a.seed)

if __name__=='__main__':main()
