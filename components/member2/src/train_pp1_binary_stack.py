#!/usr/bin/env python3
"""
PP1 ENGINEERING PROTOTYPE: RF + LightGBM + XGBoost + PyTorch LSTM stacking.

Group-disjoint test sessions and group-disjoint out-of-fold meta training.
"""

import argparse
import csv
import json
import math
import random
import warnings
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             average_precision_score)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.linear_model import LogisticRegression
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence

SOURCE_SERVICES = [
    "iam.amazonaws.com", "sts.amazonaws.com", "ec2.amazonaws.com",
    "cloudtrail.amazonaws.com", "s3.amazonaws.com", "signin.amazonaws.com",
    "secretsmanager.amazonaws.com", "kms.amazonaws.com", "ssm.amazonaws.com",
    "lambda.amazonaws.com",
]
CREDENTIAL_EVENTS = {"ConsoleLogin","AssumeRole","CreateAccessKey","CreateLoginProfile","GetUser"}
IDENTITY_MUTATIONS = {"CreateUser","CreateAccessKey","CreateLoginProfile","AttachUserPolicy", "PutUserPolicy","UpdateLoginProfile","UpdateAssumeRolePolicy","CreatePolicyVersion","SetDefaultPolicyVersion"}
LOGGING_MUTATIONS = {"StopLogging","DeleteTrail","PutEventSelectors","DeleteLogGroup","DeleteFlowLogs","DeleteResolverQueryLogConfig"}
DISCOVERY_EVENTS = {"DescribeInstances","DescribeSecurityGroups","DescribeVpcs","DescribeTrails","ListBuckets","ListRoles","ListUsers","ListPolicies","GetTrailStatus","DescribeRouteTables"}
SECRET_ACCESS = {"GetSecretValue","Decrypt","GetParameter","GetParameters"}
FEATURES = [
    "event_count","unique_api_count","unique_service_count","write_count","write_rate",
    "error_count","error_rate","distinct_regions","mean_gap_s","max_gap_s","median_gap_s",
    "credential_api_count","identity_mutation_count","logging_mutation_count",
    "discovery_api_count","secret_access_count","api_calls_per_minute",
] + ["svc_"+str(i) for i in range(len(SOURCE_SERVICES))]

SEQ_DIM = 7 + len(SOURCE_SERVICES)
MAX_SEQ = 40


def read_rows(path):
    with path.open(newline="",encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def is_true(s):
    return str(s).strip().lower() in ("true","1","yes")


def timeparse(t):
    return datetime.fromisoformat(str(t).replace("Z","+00:00"))


def floor_t(t,window_minutes):
    dt=timeparse(t)
    return dt.replace(minute=(dt.minute//window_minutes)*window_minutes,second=0,microsecond=0)


def featureize_group(group, window_minutes):
    group=sorted(group,key=lambda r:(r['event_time'],r['event_id']))
    names=[r['event_name'] for r in group]
    sources=[r['event_source'] for r in group]
    errs=np.asarray([bool(r['error_code']) for r in group],dtype=float)
    writes=np.asarray([not is_true(r['read_only']) for r in group],dtype=float)
    times=[timeparse(r['event_time']) for r in group]
    gaps=np.asarray([(b-a).total_seconds() for a,b in zip(times,times[1:])],dtype=float)
    count=len(group)
    vals={
        "event_count":count,"unique_api_count":len(set(names)),
        "unique_service_count":len(set(sources)),
        "write_count":int(writes.sum()),"write_rate":float(writes.mean()),
        "error_count":int(errs.sum()),"error_rate":float(errs.mean()),
        "distinct_regions":len(set(r['aws_region'] for r in group)),
        "mean_gap_s":float(gaps.mean()) if len(gaps) else 0.,
        "max_gap_s":float(gaps.max()) if len(gaps) else 0.,
        "median_gap_s":float(np.median(gaps)) if len(gaps) else 0.,
        "credential_api_count":sum(n in CREDENTIAL_EVENTS for n in names),
        "identity_mutation_count":sum(n in IDENTITY_MUTATIONS for n in names),
        "logging_mutation_count":sum(n in LOGGING_MUTATIONS for n in names),
        "discovery_api_count":sum(n in DISCOVERY_EVENTS for n in names),
        "secret_access_count":sum(n in SECRET_ACCESS for n in names),
        "api_calls_per_minute":count/float(window_minutes),
    }
    vals.update({"svc_"+str(i):sum(s==svc for s in sources) for i,svc in enumerate(SOURCE_SERVICES)})
    seq=[]
    prev=times[0]

    for r,t in zip(group,times):
        delta=min(max(0.,(t-prev).total_seconds()),120.)/120.
        prev=t
        name=r['event_name']
        v=[
            float(not is_true(r['read_only'])),
            float(bool(r['error_code'])),
            float(name in CREDENTIAL_EVENTS),
            float(name in IDENTITY_MUTATIONS),
            float(name in LOGGING_MUTATIONS),
            float(name in DISCOVERY_EVENTS),
            float(delta),
        ] + [float(r['event_source']==svc) for svc in SOURCE_SERVICES]
        # Chronological order and bounded inter-event intervals are available
        # to the LSTM; absolute timestamps and source metadata are excluded.
        seq.append(v)

    # Bounded temporal input; retain earliest and latest portions when long.
    if len(seq)>MAX_SEQ:
        seq=seq[:MAX_SEQ//2]+seq[-MAX_SEQ//2:]
    return vals, np.asarray(seq,dtype=np.float32)


def prepare_windows(rows, minutes):
    required={'simulation_session_id','event_id','event_time','event_name','event_source','read_only','error_code','injected_attack_event','event_origin','aws_region'}

    if not rows or not required.issubset(rows[0]):
        raise ValueError('Missing controlled synthetic experiment CSV fields')

    if any(r['event_origin']!='controlled_synthetic' for r in rows):
        raise ValueError('Non-synthetic input prohibited in PP1 demo')
    windows=defaultdict(list)

    for r in rows:
        windows[(r['simulation_session_id'], floor_t(r['event_time'], minutes))].append(r)
    dataset=[]; seqs=[]

    for (sid,start), group in sorted(windows.items()):
        features, seq=featureize_group(group,minutes)
        attack_events=[r for r in group if r['injected_attack_event']=='1']
        y=int(len(attack_events)>0)
        labels=set(r['attack_session_class'] for r in attack_events if r['attack_session_class'])

        if len(labels)>1:
            raise ValueError('Multiple categories in one synthetic window')
        dataset.append({
            'session_id':sid,'window_start':start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'label_binary':y,'true_injected_class':next(iter(labels)) if labels else '',
            'simulated_attack_session':int(sid.startswith('synthetic_attack_')),
            **features
        })
        seqs.append(seq)
    return pd.DataFrame(dataset), seqs


def pad_sequences(seqs):
    lengths=np.asarray([len(s) for s in seqs],dtype=np.int64)
    padded=np.zeros((len(seqs),MAX_SEQ,SEQ_DIM),dtype=np.float32)

    for i,seq in enumerate(seqs):
        padded[i,:len(seq)] = seq
    return padded,lengths


class WindowLSTM(nn.Module):
    def __init__(self,features=SEQ_DIM,hidden=20):
        super().__init__()
        self.lstm=nn.LSTM(input_size=features,hidden_size=hidden,batch_first=True)
        self.head=nn.Sequential(nn.Linear(hidden,10),nn.ReLU(),nn.Linear(10,1))

    def forward(self,x,lengths):
        packed=pack_padded_sequence(x,lengths.cpu(),batch_first=True,enforce_sorted=False)
        _,(hidden,_) = self.lstm(packed)
        return self.head(hidden[-1]).squeeze(1)


def train_lstm(x,len_arr,y,seed=4010,epochs=4):
    torch.manual_seed(seed)
    model=WindowLSTM()
    optimizer=torch.optim.Adam(model.parameters(),lr=.008)
    ratio=(len(y)-sum(y))/max(1,sum(y))
    criterion=nn.BCEWithLogitsLoss(pos_weight=torch.tensor(float(min(8.,max(.5,ratio)))))
    order=np.arange(len(y))
    model.train()
    for ep in range(epochs):
        np.random.default_rng(seed+ep).shuffle(order)

        for part in np.array_split(order,max(1,math.ceil(len(order)/64))):

            if not len(part):continue
            bx=torch.tensor(x[part]);bl=torch.tensor(len_arr[part]);by=torch.tensor(y[part],dtype=torch.float32)
            optimizer.zero_grad()
            loss=criterion(model(bx,bl),by)
            loss.backward();optimizer.step()

    model.eval()
    return model


def lstm_predict(model,x,lengths):
    preds=[]
    with torch.no_grad():
        for s in range(0,len(x),128):
            p=torch.sigmoid(model(torch.tensor(x[s:s+128]),torch.tensor(lengths[s:s+128])))
            preds.extend(p.numpy().tolist())
    return np.asarray(preds,dtype=float)


def construct_models(seed):
    return [
        ('Random Forest', RandomForestClassifier(n_estimators=130,min_samples_leaf=2,random_state=seed,n_jobs=2,class_weight='balanced_subsample')),
        ('LightGBM', LGBMClassifier(n_estimators=90,learning_rate=.06,max_depth=4,num_leaves=15,min_child_samples=8,
                                   random_state=seed,verbosity=-1,n_jobs=2,class_weight='balanced')),
        ('XGBoost', XGBClassifier(n_estimators=90,learning_rate=.07,max_depth=3,subsample=.85,colsample_bytree=.9,
                                  random_state=seed,tree_method='hist',eval_metric='logloss',n_jobs=2)),
    ]


def evaluate(y,p):
    hard=(p>=.5).astype(int)
    cm=confusion_matrix(y,hard,labels=[0,1]).tolist()
    return {
        'accuracy':float(accuracy_score(y,hard)),
        'precision':float(precision_score(y,hard,zero_division=0)),
        'recall':float(recall_score(y,hard,zero_division=0)),
        'f1':float(f1_score(y,hard,zero_division=0)),
        'roc_auc':float(roc_auc_score(y,p)) if len(set(y))>1 else None,
        'average_precision':float(average_precision_score(y,p)) if len(set(y))>1 else None,
        'confusion_matrix_0_1':cm,
    }


def train(csv_path,output_dir,minutes=5,seed=4010,lstm_epochs=4,folds=3):
    torch.set_num_threads(min(2,max(1,torch.get_num_threads())))
    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed)
    rows=read_rows(csv_path)
    df, seqs=prepare_windows(rows,minutes)

    if len(df)<100:
        raise ValueError('Insufficient controlled simulation windows')
    sess=df[['session_id','simulated_attack_session']].drop_duplicates().reset_index(drop=True)
    train_sess,test_sess=train_test_split(sess['session_id'],test_size=.2,random_state=seed,
        stratify=sess['simulated_attack_session'])
    train_mask=df.session_id.isin(set(train_sess)).to_numpy()
    test_mask=~train_mask

    assert not set(df.session_id[train_mask]) & set(df.session_id[test_mask])
    x=df[FEATURES].to_numpy(dtype=float)
    y=df.label_binary.to_numpy(dtype=int)
    full_seq,full_lens=pad_sequences(seqs)
    xtr=x[train_mask];xte=x[test_mask]
    ytr=y[train_mask];yte=y[test_mask]
    groups=df.session_id[train_mask].to_numpy()
    strn=full_seq[train_mask];sten=full_seq[test_mask]
    ltr=full_lens[train_mask];lte=full_lens[test_mask]

    if ytr.sum()<folds or yte.sum()<3:
        raise ValueError('Insufficient positive windows for model validation')
    print(f'Windows: {len(df)} | Train={len(xtr)}, Test={len(xte)} | Positive train={ytr.sum()}, test={yte.sum()}')

    print(f'Independent sessions: train={len(set(groups))}, test={len(set(df.session_id[test_mask]))}')
    oof=np.zeros((len(xtr),4),dtype=float)
    test_probs=np.zeros((len(xte),4),dtype=float)
    model_names=['Random Forest','LightGBM','XGBoost','LSTM']
    splitter=StratifiedGroupKFold(n_splits=folds,shuffle=True,random_state=seed)
    full_model_artifacts={}

    for f,(fit_idx,val_idx) in enumerate(splitter.split(xtr,ytr,groups),1):
        if len(set(ytr[fit_idx]))<2 or len(set(ytr[val_idx]))<2:
            raise ValueError('Group fold without both classes; increase session count')
        assert not set(groups[fit_idx]) & set(groups[val_idx])

        for j,(name,model) in enumerate(construct_models(seed+f)):
            model.fit(xtr[fit_idx],ytr[fit_idx])
            oof[val_idx,j]=model.predict_proba(xtr[val_idx])[:,1]
        lstm=train_lstm(strn[fit_idx],ltr[fit_idx],ytr[fit_idx],seed+f,lstm_epochs)
        oof[val_idx,3]=lstm_predict(lstm,strn[val_idx],ltr[val_idx])
        print(f'Out-of-fold group split {f}/{folds} finished')

    for j,(name,model) in enumerate(construct_models(seed)):
        model.fit(xtr,ytr)
        test_probs[:,j]=model.predict_proba(xte)[:,1]
        full_model_artifacts[name]=model
        print(f'{name} trained')
    final_lstm=train_lstm(strn,ltr,ytr,seed,lstm_epochs)

    test_probs[:,3]=lstm_predict(final_lstm,sten,lte)
    print('LSTM trained')
    meta=LogisticRegression(C=.7,max_iter=2000,random_state=seed)
    meta.fit(oof,ytr)

    # crucial: meta is trained on OOF, never on in-sample base predictions.
    stacked_prob=meta.predict_proba(test_probs)[:,1]
    metrics={name:evaluate(yte,test_probs[:,i]) for i,name in enumerate(model_names)}
    metrics['Stacking ensemble']=evaluate(yte,stacked_prob)
    output_dir.mkdir(parents=True,exist_ok=True)
    df.to_csv(output_dir/'window_features_RESEARCH_PROTO.csv',index=False,encoding='utf-8-sig')
    df_tr=df.loc[train_mask,['session_id','window_start','label_binary']].copy()

    for i,n in enumerate(model_names): df_tr[f'oof_{n.replace(" ","_")}']=oof[:,i]
    df_tr.to_csv(output_dir/'oof_meta_training_RESEARCH_PROTO.csv',index=False,encoding='utf-8-sig')
    df_test=df.loc[test_mask,['session_id','window_start','label_binary','true_injected_class']].copy()
    df_test['predicted_binary']=(stacked_prob>=.5).astype(int)
    df_test['stacked_malicious_score']=stacked_prob

    for i,n in enumerate(model_names): df_test[f'prob_{n.replace(" ","_")}']=test_probs[:,i]
    df_test.to_csv(output_dir/'test_predictions_RESEARCH_PROTO.csv',index=False,encoding='utf-8-sig')
    findings=df_test[['session_id','window_start','predicted_binary','stacked_malicious_score']].copy()
    findings['model_disagreement']=test_probs.std(axis=1)
    findings['finding_type']='SYNTHETIC_PROTOTYPE_ONLY'
    findings['research_class_prediction']='NOT_IMPLEMENTED_BINARY_ONLY'
    findings['evidence_status']='synthetic_ground_truth_only'
    findings.to_csv(output_dir/'member4_findings_PROTO_ONLY.csv',index=False,encoding='utf-8-sig')
    joblib.dump({'models':full_model_artifacts,'meta':meta,'features':FEATURES},output_dir/'tree_models_and_meta_PROTO.joblib')
    torch.save({'state_dict':final_lstm.state_dict(),'sequence_dim':SEQ_DIM,'max_seq':MAX_SEQ},
               output_dir/'lstm_PROTO.pt')
    (output_dir/'feature_whitelist.json').write_text(json.dumps({'numeric_features':FEATURES,
            'excluded':['dataset_source','event_origin','injected_attack_event','scenario_id','attack_session_class',
                        'event_id','identity_arn','actor_user','simulation_session_id','generation_seed',
                        'ground_truth_source','label_binary','user_agent']},indent=2),encoding='utf-8')
    report={
        'dataset_type':'ALL-SYNTHETIC_PP1_ENGINEERING_PROTOTYPE',
        'real_world_attack_accuracy_estimate':False,
        'n_events':len(rows),'total_windows':len(df),
        'train_windows':len(xtr),'test_windows':len(xte),
        'positive_train_windows':int(ytr.sum()),'positive_test_windows':int(yte.sum()),
        'train_sessions':len(set(groups)),'test_sessions':len(set(df.session_id[test_mask])),
        'stratified_group_split':True,'oof_group_folds':folds,
        'lstm_epochs':lstm_epochs,'window_minutes':minutes,
        'metrics':metrics,
        'warnings':[
            'Synthetic benign and synthetic attacks with designed behavioral patterns; metrics reflect in-distribution simulator behavior only.',
            'No real benign or approved Stratus attack samples were used for training or test.',
            'Avoid comparing these metrics with true real-world detection without independent external evaluation.',
            'Synthetic sessions can share generator biases and attack patterns; group separation does not remove generator bias.',
            'This PP1 stage implements binary detection only. Five attack category prediction remains later work.',
            'Model scores are uncalibrated and should not be interpreted as validated risk probabilities.',
        ],
    }
    (output_dir/'experiment_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('\nPP1 CONTROLLED SYNTHETIC TEST METRICS (NOT REAL-WORLD):')

    for model,m in metrics.items():
        print(f"  {model:20} F1={m['f1']:.3f} Precision={m['precision']:.3f} Recall={m['recall']:.3f}")
    print('Artifacts:',output_dir)
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data',type=Path,default=Path('Data/Synthetic/pp1_experiment/synthetic_experiment_events.csv'))
    ap.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_binary'))
    ap.add_argument('--window-minutes',type=int,default=5)
    ap.add_argument('--lstm-epochs',type=int,default=4)
    ap.add_argument('--seed',type=int,default=4010)
    args=ap.parse_args()

    if args.window_minutes<1 or 60%args.window_minutes!=0:
        raise ValueError('window minutes must be a divisor of 60')
    train(args.data,args.output_dir,args.window_minutes,args.seed,args.lstm_epochs)

if __name__=='__main__':
    main()
