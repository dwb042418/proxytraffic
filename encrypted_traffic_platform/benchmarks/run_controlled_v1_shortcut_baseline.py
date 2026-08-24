#!/usr/bin/env python3

from pathlib import Path
import csv
import json

import numpy as np

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[2]

DATA = (
    ROOT
    / 'docs/benchmarks/proxytraffic_controlled_v1'
    / 'remote_audit/observed_stats.tsv'
)

OUT = (
    ROOT
    / 'docs/benchmarks/proxytraffic_controlled_v1'
    / 'shortcut_baseline'
)

OUT.mkdir(
    parents=True,
    exist_ok=True,
)


FEATURES = [
    'packet_count',
    'byte_count',
    'flow_count',
    'tcp_stream_count',
    'duration',
    'pcap_size_bytes',
]

LABELS = [
    'vless',
    'shadowsocks',
    'trojan',
]


rows = []

with DATA.open(
    newline='',
    encoding='utf-8',
) as f:

    for row in csv.DictReader(
        f,
        delimiter='\t',
    ):
        rows.append(row)


def matrix(rows):

    x = np.asarray(
        [
            [
                float(r[name])
                for name in FEATURES
            ]
            for r in rows
        ],
        dtype=np.float64,
    )

    y = np.asarray(
        [
            r['class_label']
            for r in rows
        ]
    )

    return x, y


def evaluate(
    name,
    model,
    train_rows,
    test_rows,
):

    x_train, y_train = matrix(
        train_rows
    )

    x_test, y_test = matrix(
        test_rows
    )

    model.fit(
        x_train,
        y_train,
    )

    pred = model.predict(
        x_test
    )

    result = {
        'model':
            name,

        'train_samples':
            len(train_rows),

        'test_samples':
            len(test_rows),

        'accuracy':
            float(
                accuracy_score(
                    y_test,
                    pred,
                )
            ),

        'balanced_accuracy':
            float(
                balanced_accuracy_score(
                    y_test,
                    pred,
                )
            ),

        'macro_f1':
            float(
                f1_score(
                    y_test,
                    pred,
                    average='macro',
                )
            ),

        'classification_report':
            classification_report(
                y_test,
                pred,
                labels=LABELS,
                output_dict=True,
                zero_division=0,
            ),

        'confusion_matrix':
            confusion_matrix(
                y_test,
                pred,
                labels=LABELS,
            ).tolist(),
    }

    return result


primary_train = [
    r
    for r in rows
    if r['primary_split']
    == 'train'
]

primary_test = [
    r
    for r in rows
    if r['primary_split']
    == 'test'
]


robust_train = [
    r
    for r in rows
    if r['robustness_split']
    == 'train'
]

robust_test = [
    r
    for r in rows
    if r['robustness_split']
    == 'test'
]


models = {
    'logistic_regression':
        Pipeline([
            (
                'scale',
                StandardScaler(),
            ),
            (
                'model',
                LogisticRegression(
                    max_iter=5000,
                    random_state=42,
                ),
            ),
        ]),

    'random_forest':
        RandomForestClassifier(
            n_estimators=500,
            max_depth=6,
            min_samples_leaf=3,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        ),
}


results = {
    'features':
        FEATURES,

    'primary': [],

    'perturbation_holdout': [],
}


for name, model in models.items():

    result = evaluate(
        name,
        model,
        primary_train,
        primary_test,
    )

    results[
        'primary'
    ].append(
        result
    )


for name, model in models.items():

    result = evaluate(
        name,
        model,
        robust_train,
        robust_test,
    )

    results[
        'perturbation_holdout'
    ].append(
        result
    )


output = (
    OUT
    / 'shortcut_baseline_results.json'
)

output.write_text(
    json.dumps(
        results,
        indent=2,
    )
    + '\n'
)


for section in [
    'primary',
    'perturbation_holdout',
]:

    print(
        '=====',
        section,
        '====='
    )

    for result in results[
        section
    ]:

        print(
            result['model'],
            'accuracy=',
            round(
                result['accuracy'],
                4,
            ),
            'balanced_accuracy=',
            round(
                result[
                    'balanced_accuracy'
                ],
                4,
            ),
            'macro_f1=',
            round(
                result[
                    'macro_f1'
                ],
                4,
            ),
        )

        print(
            'confusion_matrix='
        )

        for row in result[
            'confusion_matrix'
        ]:
            print(row)


print(
    'SHORTCUT_BASELINE_COMPLETE'
)
