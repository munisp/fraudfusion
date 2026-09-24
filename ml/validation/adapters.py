"""Dataset adapters: map external fraud datasets onto the canonical
fraudfusion transaction schema used by fraud_net
(NUMERIC_FEATURES / CATEGORICAL_FEATURES from ml.data.synthetic_nigeria).

Canonical output columns (superset; missing model features are zero-filled
and unknown categoricals map to UNK index 0, so honest degradation is
visible rather than hidden):
  ts (datetime64), sender_id, receiver_id, amount_ngn, channel, sender_bank,
  receiver_bank, sender_state, receiver_state, device_os, is_fraud (0/1),
  fraud_typology (str), plus any NUMERIC_FEATURES the source supports.

NO dataset is auto-downloaded: PaySim and IEEE-CIS both require a Kaggle
account/login. Supply the file path; the adapter prints exact instructions if
the file is missing. See docs/ML_REALDATA.md.
"""
from __future__ import annotations

import abc
from pathlib import Path

import numpy as np
import pandas as pd

from ml.data.synthetic_nigeria import (CATEGORICAL_FEATURES, NUMERIC_FEATURES)

PAYSIM_INSTRUCTIONS = """\
PaySim mobile-money fraud dataset (6.3M txns):
  1. Kaggle account required. `pip install kaggle` and place ~/.kaggle/kaggle.json.
  2. kaggle datasets download -d ealaxi/paysim1 -p <dir> && unzip <dir>/paysim1.zip -d <dir>
  3. Pass --dataset paysim --file <dir>/PS_20174392719_1491204439457_log.csv
  Note: PaySim amounts are in an anonymised currency unit, NOT NGN — treat
  amount_ngn here as a proxy unit; recalibrate thresholds on real NGN data.
"""

IEEE_INSTRUCTIONS = """\
IEEE-CIS fraud detection (Kaggle competition, Vesta):
  1. Kaggle account required. `pip install kaggle` and place ~/.kaggle/kaggle.json.
  2. kaggle competitions download -c ieee-fraud-detection -p <dir> && unzip -o <dir>/ieee-fraud-detection.zip -d <dir>
  3. Pass --dataset ieee-cis --file <dir>/train_transaction.csv
  Caveat: most fraudfusion behavioural features (velocity windows, device
  anomalies) have no IEEE analogue and are zero-filled — expect degraded
  metrics vs in-distribution data. This adapter is a schema/replay check.
"""


class DatasetAdapter(abc.ABC):
    """Load an external dataset into the canonical transaction schema."""

    name: str = "abstract"

    @abc.abstractmethod
    def load(self, path: str) -> pd.DataFrame:
        """Return canonical-schema DataFrame with ts + is_fraud columns."""

    def _missing(self, path: str, instructions: str):
        if not Path(path).exists():
            raise FileNotFoundError(
                f"{self.name} file not found: {path}\n\nHow to obtain it:\n"
                + instructions)


class SyntheticAdapter(DatasetAdapter):
    """The repo's own generated parquet (ml/data/generated) — sanity floor."""

    name = "synthetic"

    def load(self, path: str) -> pd.DataFrame:
        p = Path(path)
        if p.is_dir():
            p = p / "transactions.parquet"
        if not p.exists():
            raise FileNotFoundError(
                f"synthetic parquet not found: {p} — run "
                "`python -m ml.data.synthetic_nigeria --out <dir>` first")
        df = pd.read_parquet(p)
        if "label_available_at" in df.columns:
            # honour label lag: fraud labels only usable after confirmation
            df["is_fraud"] = np.where(
                (df["is_fraud"] == 1) &
                (df["label_available_at"] <= df["ts"].max()),
                df["is_fraud"], 0)
        return df


class PaySimAdapter(DatasetAdapter):
    """PaySim (Kaggle ealaxi/paysim1) -> canonical schema."""

    name = "paysim"
    CHANNEL_MAP = {"CASH_OUT": "agent", "CASH_IN": "agent",
                   "TRANSFER": "nip", "PAYMENT": "pos", "DEBIT": "nip"}

    def load(self, path: str) -> pd.DataFrame:
        self._missing(path, PAYSIM_INSTRUCTIONS)
        df = pd.read_csv(path)
        t0 = pd.Timestamp("2024-01-01")
        out = pd.DataFrame(dict(
            ts=t0 + pd.to_timedelta(df["step"], unit="h"),
            sender_id=df["nameOrig"].astype(str),
            receiver_id=df["nameDest"].astype(str),
            amount_ngn=df["amount"].astype(float),
            channel=df["type"].map(self.CHANNEL_MAP).fillna("nip"),
            is_fraud=df["isFraud"].astype(int),
            fraud_typology=np.where(df["isFraud"] == 1, "paysim_fraud", "legit"),
        ))
        out["sender_bank"] = "paysim_bank"
        out["receiver_bank"] = "paysim_bank"
        out["sender_state"] = "paysim"
        out["receiver_state"] = "paysim"
        out["device_os"] = "android"
        out["hour"] = out["ts"].dt.hour
        out["dow"] = out["ts"].dt.dayofweek
        out["is_month_end"] = (out["ts"].dt.day >= 25).astype(int)
        out["is_market_day"] = out["dow"].isin([1, 4]).astype(int)
        return out


class IEEECISAdapter(DatasetAdapter):
    """IEEE-CIS (Kaggle ieee-fraud-detection) -> canonical schema."""

    name = "ieee-cis"

    def load(self, path: str) -> pd.DataFrame:
        self._missing(path, IEEE_INSTRUCTIONS)
        df = pd.read_csv(path)
        t0 = pd.Timestamp("2024-01-01")
        card4 = df.get("card4", pd.Series("unknown", index=df.index))
        out = pd.DataFrame(dict(
            ts=t0 + pd.to_timedelta(df["TransactionDT"], unit="s"),
            sender_id="C" + df["card1"].astype(str),
            receiver_id="M" + df.get("addr2", 0).astype(str),
            amount_ngn=df["TransactionAmt"].astype(float),
            channel=np.where(card4.isin(["visa", "mastercard"]), "web", "web"),
            is_fraud=df["isFraud"].astype(int),
            fraud_typology=np.where(df["isFraud"] == 1, "ieee_fraud", "legit"),
        ))
        out["sender_bank"] = card4.astype(str)
        out["receiver_bank"] = "ieee_merchant"
        out["sender_state"] = df.get("addr1", 0).astype(str)
        out["receiver_state"] = "ieee"
        out["device_os"] = df.get("DeviceInfo", "web_browser").astype(str) \
            .str.split().str[0].str.lower()
        out["hour"] = out["ts"].dt.hour
        out["dow"] = out["ts"].dt.dayofweek
        out["is_month_end"] = (out["ts"].dt.day >= 25).astype(int)
        out["is_market_day"] = out["dow"].isin([1, 4]).astype(int)
        return out


ADAPTERS = {a.name: a for a in
            (SyntheticAdapter(), PaySimAdapter(), IEEECISAdapter())}


def to_model_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Fill any missing NUMERIC/CATEGORICAL feature columns (zeros / 'unknown')
    and compute log_amount if absent."""
    df = df.copy()
    if "log_amount" not in df.columns:
        df["log_amount"] = np.log1p(df["amount_ngn"].astype(float))
    for f in NUMERIC_FEATURES:
        if f not in df.columns:
            df[f] = 0.0
    for c in CATEGORICAL_FEATURES:
        if c not in df.columns:
            df[c] = "unknown"
    return df
