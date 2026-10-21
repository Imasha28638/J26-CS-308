#!/usr/bin/env python3
"""Quick quality report for a canonical CloudTrail event CSV."""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd

def main():
    p = argparse.ArgumentParser()
    p.add_argument("csv_file", type=Path)
    args = p.parse_args()

    df = pd.read_csv(args.csv_file, low_memory=False)
    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns):,}")

    print("\nTop event sources:")
    print(df["event_source"].value_counts(dropna=False).head(15).to_string())

    print("\nTop event names:")
    print(df["event_name"].value_counts(dropna=False).head(20).to_string())

    print("\nBinary labels:")
    print(df["label_binary"].value_counts(dropna=False).to_string())

    print("\nAttack classes:")
    print(df["attack_class"].value_counts(dropna=False).to_string())

    print("\nMissing values in core columns:")
    core = ["event_time", "event_name", "event_source", "aws_region",
            "source_ip_address", "identity_type", "identity_arn"]
    missing = df[core].isna().mean().sort_values(ascending=False) * 100
    print(missing.round(2).astype(str).add("%").to_string())

    dup_cols = [c for c in ["event_id", "dataset_source"] if c in df.columns]
    if "event_id" in df.columns:
        nonempty = df["event_id"].dropna().astype(str)
        nonempty = nonempty[nonempty.str.len() > 0]
        print(f"\nDuplicate non-empty event_id values: {nonempty.duplicated().sum():,}")

if __name__ == "__main__":
    main()
