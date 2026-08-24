#!/usr/bin/env python3

from pathlib import Path
from collections import defaultdict
import csv

import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
)

ROOT = Path(__file__).resolve().parents[2]

DATA = (
    ROOT
    / 'docs/benchmarks/proxytraffic_controlled_v1'
    / 'remote_audit/observed_stats.tsv'
)

FEATURE_SETS = {
    'packet_count':
        ['packet_count'],

    'byte_count':
        ['byte_count'],

    'duration':
        ['duration'],

    'pcap_size':
        ['pcap_size_bytes'],

    'flow_structure':
        ['flow_count', 'tcp_stream_count'],

    'volume':
        [
            'packet_count',
            'byte_count',
            'pcap_size_bytes',
        ],

    'volume_duration':
        [
            'packet_count',
            'byte_count',
            'pcap_size_bytes',
            'duration',
        ],

    'all':
        [
            'packet_count',
            'byte_count',
            'flow_count',
            'tcp_stream_count',
            'duration',
            'pcap_size_bytes',
        ],
}

ALL_FEATURES = FEATURE_SETS['all']

rows = []

with DATA.open(newline='') as f:
    rows = list(
        csv.DictReader(
            f,
            delimiter='\t',
        )
    )


def matrix(data, features):

    x = np.asarray(
        [
            [
                float(r[f])
                for f in features
            ]
            for r in data
        ],
        dtype=np.float64,
    )

    y = np.asarray(
        [
            r['class_label']
            for r in data
        ]
    )

    return x, y


def rf():

    return RandomForestClassifier(
        n_estimators=500,
        max_depth=6,
        min_samples_leaf=3,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )


def evaluate(train, test, features):

    xtr, ytr = matrix(
        train,
        features,
    )

    xte, yte = matrix(
        test,
        features,
    )

    model = rf()

    model.fit(
        xtr,
        ytr,
    )

    pred = model.predict(
        xte
    )

    return (
        accuracy_score(
            yte,
            pred,
        ),
        balanced_accuracy_score(
            yte,
            pred,
        ),
        f1_score(
            yte,
            pred,
            average='macro',
        ),
        model,
        xte,
        yte,
    )


print('===== FEATURE SET ABLATION =====')

primary_train = [
    r for r in rows
    if r['primary_split'] == 'train'
]

primary_test = [
    r for r in rows
    if r['primary_split'] == 'test'
]

robust_train = [
    r for r in rows
    if r['robustness_split'] == 'train'
]

robust_test = [
    r for r in rows
    if r['robustness_split'] == 'test'
]

for name, features in FEATURE_SETS.items():

    a = evaluate(
        primary_train,
        primary_test,
        features,
    )

    b = evaluate(
        robust_train,
        robust_test,
        features,
    )

    print(
        name,
        'primary_f1=',
        round(a[2], 4),
        'robust_f1=',
        round(b[2], 4),
    )


print()
print('===== PER PROFILE PRIMARY =====')

profiles = sorted({
    r['profile']
    for r in rows
})

for profile in profiles:

    train = [
        r for r in rows
        if r['profile'] == profile
        and r['primary_split'] == 'train'
    ]

    test = [
        r for r in rows
        if r['profile'] == profile
        and r['primary_split'] == 'test'
    ]

    result = evaluate(
        train,
        test,
        ALL_FEATURES,
    )

    print(
        profile,
        'train=', len(train),
        'test=', len(test),
        'macro_f1=',
        round(result[2], 4),
    )


print()
print('===== LEAVE ONE PROFILE OUT =====')

for holdout in profiles:

    train = [
        r for r in rows
        if r['profile'] != holdout
    ]

    test = [
        r for r in rows
        if r['profile'] == holdout
    ]

    result = evaluate(
        train,
        test,
        ALL_FEATURES,
    )

    print(
        'holdout=',
        holdout,
        'test=', len(test),
        'macro_f1=',
        round(result[2], 4),
    )


print()
print('===== PRIMARY PERMUTATION IMPORTANCE =====')

result = evaluate(
    primary_train,
    primary_test,
    ALL_FEATURES,
)

model = result[3]
xte = result[4]
yte = result[5]

perm = permutation_importance(
    model,
    xte,
    yte,
    scoring='f1_macro',
    n_repeats=30,
    random_state=42,
    n_jobs=-1,
)

order = np.argsort(
    perm.importances_mean
)[::-1]

for i in order:
    print(
        ALL_FEATURES[i],
        'importance=',
        round(
            perm.importances_mean[i],
            4,
        ),
        'std=',
        round(
            perm.importances_std[i],
            4,
        ),
    )

print(
    'SHORTCUT_DIAGNOSTICS_COMPLETE'
)
