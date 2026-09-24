"""Realistic synthetic Nigerian transaction / KYC / credit data generator.

Models real-world distributions rather than toy randoms:
  * NGN amounts: log-normal, kobo rounding (2dp), salary-cycle end-of-month
    spikes, market-day weekly seasonality.
  * Nigerian banks (Access, GTB, Zenith, First Bank, Kuda, OPay, PalmPay,
    Moniepoint, UBA, Stanbic), NUBAN 10-digit accounts, format-valid BVN/NIN.
  * Geo distribution over states/cities, Lagos-weighted.
  * Channels: USSD (*737# style), POS, mobile app, web, NIP instant transfer,
    agent banking.
  * Device fingerprints with emulator / device-farm anomalies.
  * Fraud typologies: mule networks (fan-in / fan-out within 24-72h, layering
    hops), 419 advance-fee, SIM-swap -> account takeover sequences, bust-out
    credit behaviour, chargeback bursts, PEP / sanctioned-entity contamination.
  * ~2% label noise.

v2 additions (dataset_version=2):
  * Agent float ledger: ~1.5% of accounts are agent-banking operators; agent
    txns carry cash-in/cash-out direction, per-agent float balance cycles
    (depletion -> rebalance reset), and agent fees.
  * POS fee/charge patterns: 0.5% merchant charge capped at N2,000, N50
    electronic-money-transfer levy on transfers >= N10,000, terminal/merchant
    IDs.
  * USSD session semantics: session IDs shared by rapid multi-step bursts,
    session durations, step counts, failed-PIN sequences (elevated on fraud).
  * Per-account salary-day crediting: salaried accounts receive a monthly
    salary credit on their own salary_day + a 3-day post-salary spend uplift.
  * Label lag: fraud labels are confirmed 7-30 days after the transaction
    (label_available_at column); legit labels are immediate.
  * Typology-weighted label noise (~2% overall, concentrated in pos/agent
    channels where disputes are common).

Deterministic seed. Outputs parquet + temporal train/val/test split.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 20240517
DATASET_VERSION = 2

BANKS = [
    ("Access Bank", "044"), ("GTBank", "058"), ("Zenith Bank", "057"),
    ("First Bank", "011"), ("UBA", "033"), ("Kuda", "50211"),
    ("OPay", "999992"), ("PalmPay", "999991"), ("Moniepoint", "50515"),
    ("Stanbic IBTC", "221"),
]

# (state, city, weight) -- Lagos-heavy, mirroring Nigerian fintech volume.
GEO = [
    ("Lagos", "Lagos", 0.32), ("Lagos", "Ikeja", 0.06), ("Abuja", "Abuja", 0.10),
    ("Rivers", "Port Harcourt", 0.08), ("Kano", "Kano", 0.07),
    ("Oyo", "Ibadan", 0.07), ("Enugu", "Enugu", 0.04), ("Delta", "Warri", 0.04),
    ("Anambra", "Onitsha", 0.04), ("Kaduna", "Kaduna", 0.04),
    ("Edo", "Benin City", 0.03), ("Ogun", "Abeokuta", 0.03),
    ("Imo", "Owerri", 0.03), ("Kwara", "Ilorin", 0.02),
    ("Borno", "Maiduguri", 0.01), ("Sokoto", "Sokoto", 0.01),
    ("Plateau", "Jos", 0.01),
]

CHANNELS = ["ussd", "pos", "mobile_app", "web", "nip", "agent"]
CHANNEL_W = [0.16, 0.24, 0.28, 0.06, 0.18, 0.08]
DEVICE_OS = ["android", "ios", "feature_phone", "web_browser", "pos_terminal"]
MARKET_DAYS = {1, 4}  # Tue / Fri market days -> weekly seasonality

PEP_SURNAMES = ["Danladi", "Sadiq", "Bello-Kumo", "Ekwueme"]
SANCTIONED_FRONT_CO = ["Havana General Trading", "Mira Gold & Metals LLC"]


def nuban(rng: np.random.Generator, bank_code: str) -> str:
    """Format-valid-ish NUBAN: 10 digits with correct check-digit algorithm."""
    serial = "".join(str(d) for d in rng.integers(0, 10, 9))
    base = bank_code[-3:] + serial
    weights = [3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3]
    s = sum(int(d) * w for d, w in zip(base, weights))
    check = (10 - (s % 10)) % 10
    return serial + str(check)


def bvn(rng: np.random.Generator) -> str:  # 11-digit BVN
    return "".join(str(d) for d in rng.integers(0, 10, 11))


def nin(rng: np.random.Generator) -> str:  # 11-digit NIN
    return "".join(str(d) for d in rng.integers(0, 10, 11))


def phone(rng: np.random.Generator) -> str:
    prefix = rng.choice(["0803", "0805", "0703", "0810", "0813", "0903", "0701", "0814"])
    return prefix + "".join(str(d) for d in rng.integers(0, 10, 7))


FIRST = ["Chinedu", "Aisha", "Tunde", "Ngozi", "Ibrahim", "Funke", "Emeka",
         "Fatima", "Segun", "Adaeze", "Musa", "Kemi", "Obi", "Halima",
         "Femi", "Chioma", "Yusuf", "Bimpe", "Uche", "Zainab"]
LAST = ["Okafor", "Bello", "Adeyemi", "Eze", "Abubakar", "Adeleke", "Nwosu",
        "Olawale", "Adamu", "Ogunleye", "Ibrahim", "Chukwu", "Danjuma",
        "Balogun", "Okonkwo", "Aliyu", "Adebayo", "Udoka", "Garba", "Ojo"]


def _kobo_round(x: np.ndarray) -> np.ndarray:
    return np.round(x, 2)


def generate_accounts(n: int, rng: np.random.Generator) -> pd.DataFrame:
    rows = []
    states = [g[0] for g in GEO]
    cities = [g[1] for g in GEO]
    w = np.array([g[2] for g in GEO])
    w = w / w.sum()
    geo_idx = rng.choice(len(GEO), size=n, p=w)
    for i in range(n):
        bank_name, bank_code = BANKS[rng.integers(len(BANKS))]
        income = float(np.exp(rng.normal(12.2, 0.8)))  # log-normal monthly income NGN
        emp = rng.choice(
            ["salaried", "self_employed", "trader", "gig", "unemployed", "student"],
            p=[0.30, 0.24, 0.22, 0.10, 0.08, 0.06],
        )
        age = int(np.clip(rng.normal(35, 10), 18, 75))
        bureau = int(np.clip(rng.normal(620, 70), 300, 850))
        rows.append(dict(
            customer_id=f"C{i:06d}",
            name=f"{FIRST[rng.integers(len(FIRST))]} {LAST[rng.integers(len(LAST))]}",
            bvn=bvn(rng), nin=nin(rng), phone=phone(rng),
            bank=bank_name, bank_code=bank_code,
            nuban=nuban(rng, bank_code),
            state=states[geo_idx[i]], city=cities[geo_idx[i]],
            age=age, employment=emp, monthly_income=round(income, 2),
            bureau_score=bureau,
            salary_day=int(rng.integers(25, 29)) if emp == "salaried" else 0,
            device_os=str(rng.choice(DEVICE_OS, p=[0.55, 0.18, 0.07, 0.10, 0.10])),
            is_pep=False, is_mule=False, is_sanctioned_front=False,
            is_agent=False,
        ))
    df = pd.DataFrame(rows)
    # Agent-banking operators (~1.5%), skewed to agent-heavy institutions
    agent_idx = rng.choice(n, size=max(4, int(0.015 * n)), replace=False)
    df.loc[agent_idx, "is_agent"] = True
    # PEP / sanctioned-entity contamination (~0.4%)
    pep_idx = rng.choice(n, size=max(2, n // 250), replace=False)
    df.loc[pep_idx, "is_pep"] = True
    for j, i in enumerate(pep_idx):
        if j % 3 == 0:
            df.loc[i, "name"] = f"{FIRST[rng.integers(len(FIRST))]} {PEP_SURNAMES[j % len(PEP_SURNAMES)]}"
    front_idx = rng.choice(n, size=max(1, n // 1000), replace=False)
    df.loc[front_idx, "is_sanctioned_front"] = True
    for j, i in enumerate(front_idx):
        df.loc[i, "name"] = SANCTIONED_FRONT_CO[j % len(SANCTIONED_FRONT_CO)]
    return df


# --------------------------------------------------------------------------
# Fraud typology injectors
# --------------------------------------------------------------------------

def _build_mule_networks(accts: pd.DataFrame, rng: np.random.Generator,
                         n_networks: int = 10):
    """Pick mule accounts; each network: 1 hub + 3-6 spoke collectors.

    Mules fan-in from many victims and fan-out (layering hops) within 24-72h.
    """
    n = len(accts)
    mule_ids = set()
    networks = []
    candidates = rng.choice(n, size=n_networks * 7, replace=False)
    ci = 0
    for k in range(n_networks):
        hub = candidates[ci]; ci += 1
        spokes = candidates[ci:ci + rng.integers(3, 7)]; ci += len(spokes)
        mule_ids.add(hub)
        mule_ids.update(spokes.tolist())
        networks.append(dict(hub=hub, spokes=spokes.tolist()))
    accts.loc[sorted(mule_ids), "is_mule"] = True
    return networks


def _amount_legit(rng, size):
    """Log-normal NGN amounts with realistic mass at round figures."""
    amt = np.exp(rng.normal(9.4, 1.15, size))  # median ~ 12k NGN
    round_mask = rng.random(size) < 0.25
    amt[round_mask] = np.round(amt[round_mask] / 500) * 500
    return _kobo_round(np.clip(amt, 50, 25_000_000))


def generate_transactions(accts: pd.DataFrame, rng: np.random.Generator,
                          n_txns: int = 60000, days: int = 180,
                          start: str = "2024-01-01") -> pd.DataFrame:
    n = len(accts)
    start_ts = pd.Timestamp(start)
    # sender activity: pareto-ish (few heavy users)
    activity = rng.pareto(1.2, n) + 0.05
    activity /= activity.sum()
    senders = rng.choice(n, size=n_txns, p=activity)
    receivers = rng.integers(0, n, n_txns)
    same = senders == receivers
    receivers[same] = (receivers[same] + 1) % n

    # timestamps with salary-cycle + market-day seasonality
    day_offsets = rng.integers(0, days, n_txns)
    dates = start_ts + pd.to_timedelta(day_offsets, unit="D")
    dow = dates.dayofweek.to_numpy()
    dom = dates.day.to_numpy()
    month_end = (dom >= 25) & (dom <= 31)
    market_day = np.isin(dow, list(MARKET_DAYS))
    hour = np.clip(rng.normal(13.5, 4.2, n_txns).astype(int), 0, 23)
    # night-owl fraud-leaning tail for a small slice
    night = rng.random(n_txns) < 0.06
    hour[night] = rng.integers(0, 5, night.sum())
    ts = dates + pd.to_timedelta(hour, unit="h") + pd.to_timedelta(
        rng.integers(0, 60, n_txns), unit="m")

    amounts = _amount_legit(rng, n_txns)
    # salary-cycle spikes: bigger amounts near end-of-month
    amounts[month_end] = _kobo_round(amounts[month_end] * rng.uniform(1.3, 2.6, month_end.sum()))
    # market-day POS/agent uplift handled via channel choice below

    channels = rng.choice(CHANNELS, size=n_txns, p=CHANNEL_W)
    # USSD skews small; NIP/POS skew larger
    amt_arr = np.array(amounts)
    ussd = channels == "ussd"
    amt_arr[ussd] = np.clip(amt_arr[ussd], 50, 100_000)
    channels = np.array(channels)

    cust = accts.set_index("customer_id")
    cid = accts["customer_id"].to_numpy()
    dev_os = accts["device_os"].to_numpy()

    df = pd.DataFrame(dict(
        txn_id=[f"T{i:08d}" for i in range(n_txns)],
        ts=ts,
        sender_id=cid[senders],
        receiver_id=cid[receivers],
        amount_ngn=amt_arr,
        channel=channels,
        sender_bank=accts["bank"].to_numpy()[senders],
        receiver_bank=accts["bank"].to_numpy()[receivers],
        sender_state=accts["state"].to_numpy()[senders],
        receiver_state=accts["state"].to_numpy()[receivers],
        device_os=dev_os[senders],
        hour=hour, dow=dow,
        is_month_end=month_end.astype(int),
        is_market_day=market_day.astype(int),
        is_fraud=np.zeros(n_txns, dtype=int),
        fraud_typology="legit",
        device_emulator=np.zeros(n_txns, dtype=int),
        sim_swap_7d=np.zeros(n_txns, dtype=int),
        new_device=np.zeros(n_txns, dtype=int),
    ))
    return df


def inject_fraud(txns: pd.DataFrame, accts: pd.DataFrame,
                 networks, rng: np.random.Generator):
    """Overlay fraud typologies; sets is_fraud + fraud_typology + features."""
    n = len(accts)
    txns = txns.sort_values("ts").reset_index(drop=True)
    idx_of = {cid: i for i, cid in enumerate(accts["customer_id"])}
    cid_arr = accts["customer_id"].to_numpy()

    # --- 1. Mule networks: fan-in then layered fan-out within 24-72h --------
    fanin_flag = np.zeros(len(txns), dtype=int)
    for net in networks:
        hub_cid = cid_arr[net["hub"]]
        spoke_cids = cid_arr[np.array(net["spokes"])]
        n_events = int(rng.integers(6, 14))
        for _ in range(n_events):
            t0 = txns["ts"].iloc[0] + pd.Timedelta(
                hours=int(rng.integers(0, 24 * 174)))
            # fan-in: 4-9 victims -> hub/spokes
            for _ in range(int(rng.integers(4, 10))):
                victim = cid_arr[rng.integers(n)]
                mule = str(rng.choice(np.append(spoke_cids, hub_cid)))
                row = dict(txns.iloc[rng.integers(len(txns))])
                row.update(txn_id=f"MF{rng.integers(1e8):08d}", ts=t0 + pd.Timedelta(
                    minutes=int(rng.integers(0, 600))),
                    sender_id=victim, receiver_id=mule,
                    amount_ngn=float(_kobo_round(rng.uniform(20_000, 900_000))),
                    channel="nip", is_fraud=1, fraud_typology="mule_fanin",
                    sender_bank=accts.loc[idx_of[victim], "bank"],
                    receiver_bank=accts.loc[idx_of[mule], "bank"],
                    sender_state=accts.loc[idx_of[victim], "state"],
                    receiver_state=accts.loc[idx_of[mule], "state"])
                txns.loc[len(txns)] = row
            # layering hops: mule -> mule -> hub -> cash-out, 24-72h window
            hop_from = str(rng.choice(spoke_cids))
            for hop, (a, b) in enumerate([
                    (hop_from, hub_cid),
                    (hub_cid, str(rng.choice(spoke_cids)))]):
                row = dict(txns.iloc[rng.integers(len(txns))])
                row.update(txn_id=f"ML{rng.integers(1e8):08d}",
                           ts=t0 + pd.Timedelta(hours=int(rng.integers(6, 72))),
                           sender_id=a, receiver_id=b,
                           amount_ngn=float(_kobo_round(rng.uniform(50_000, 1_500_000))),
                           channel="nip", is_fraud=1,
                           fraud_typology="mule_layering",
                           sender_bank=accts.loc[idx_of[a], "bank"],
                           receiver_bank=accts.loc[idx_of[b], "bank"],
                           sender_state=accts.loc[idx_of[a], "state"],
                           receiver_state=accts.loc[idx_of[b], "state"])
                txns.loc[len(txns)] = row

    # --- 2. SIM-swap -> ATO sequences ---------------------------------------
    ato_victims = rng.choice(n, size=60, replace=False)
    for v in ato_victims:
        victim = cid_arr[v]
        mask = txns["sender_id"].values == victim
        vidx = np.where(mask)[0]
        if len(vidx) == 0:
            continue
        t_swap = txns["ts"].iloc[int(vidx[rng.integers(len(vidx))])]
        # post-swap burst: new device + emulator + rapid drain
        for k in range(int(rng.integers(2, 5))):
            row = dict(txns.iloc[vidx[rng.integers(len(vidx))]])
            row.update(txn_id=f"AT{rng.integers(1e8):08d}",
                       ts=t_swap + pd.Timedelta(minutes=10 + 7 * k),
                       amount_ngn=float(_kobo_round(rng.uniform(80_000, 2_000_000))),
                       channel=str(rng.choice(["mobile_app", "ussd"])),
                       is_fraud=1, fraud_typology="sim_swap_ato",
                       device_emulator=int(rng.random() < 0.45),
                       sim_swap_7d=1, new_device=1,
                       hour=int(rng.integers(0, 5)))
            txns.loc[len(txns)] = row

    # --- 3. 419 / advance-fee -----------------------------------------------
    fraudsters = rng.choice(n, size=25, replace=False)
    for f in fraudsters:
        fc = cid_arr[f]
        for _ in range(int(rng.integers(2, 6))):
            victim = cid_arr[rng.integers(n)]
            row = dict(txns.iloc[rng.integers(len(txns))])
            row.update(txn_id=f"AF{rng.integers(1e8):08d}",
                       ts=txns["ts"].iloc[0] + pd.Timedelta(
                           hours=int(rng.integers(0, 24 * 176))),
                       sender_id=victim, receiver_id=fc,
                       amount_ngn=float(_kobo_round(rng.uniform(30_000, 500_000))),
                       channel=str(rng.choice(["nip", "ussd", "agent"])),
                       is_fraud=1, fraud_typology="advance_fee_419",
                       sender_bank=accts.loc[idx_of[victim], "bank"],
                       receiver_bank=accts.loc[idx_of[fc], "bank"],
                       sender_state=accts.loc[idx_of[victim], "state"],
                       receiver_state=accts.loc[idx_of[fc], "state"])
            txns.loc[len(txns)] = row

    # --- 4. Chargeback bursts (POS) ------------------------------------------
    cb_merchants = rng.choice(n, size=15, replace=False)
    for m in cb_merchants:
        mc = cid_arr[m]
        t0 = txns["ts"].iloc[0] + pd.Timedelta(hours=int(rng.integers(0, 24 * 172)))
        for k in range(int(rng.integers(5, 12))):
            row = dict(txns.iloc[rng.integers(len(txns))])
            row.update(txn_id=f"CB{rng.integers(1e8):08d}",
                       ts=t0 + pd.Timedelta(hours=int(k * rng.uniform(1, 6))),
                       receiver_id=mc, amount_ngn=float(
                           _kobo_round(rng.uniform(15_000, 300_000))),
                       channel="pos", is_fraud=1,
                       fraud_typology="chargeback_burst")
            txns.loc[len(txns)] = row

    # --- 5. PEP / sanctioned contamination -----------------------------------
    risky = accts.index[(accts["is_pep"]) | (accts["is_sanctioned_front"])].to_numpy()
    for r in risky:
        rc = cid_arr[r]
        mask = np.where(txns["receiver_id"].values == rc)[0]
        if len(mask) == 0:
            continue
        pick = rng.choice(mask, size=min(3, len(mask)), replace=False)
        for p in pick:
            txns.loc[p, "is_fraud"] = 1
            txns.loc[p, "fraud_typology"] = "pep_sanction_exposure"

    # --- 6. Emulator / device-farm anomalies on a slice of legit ------------
    legit = txns["is_fraud"].values == 0
    farm = np.where(legit)[0]
    farm_pick = rng.choice(farm, size=int(0.004 * len(txns)), replace=False)
    txns.loc[farm_pick, "device_emulator"] = 1  # anomalous but unlabelled noise

    # --- label noise ~2% (typology/channel-weighted, still ~2% overall) ------
    # Dispute-heavy channels (pos/agent) flip more often; confirmed mule
    # fan-in rows are rarely un-labelled (they survive investigation).
    w = np.ones(len(txns))
    w *= np.where(txns["channel"].isin(["pos", "agent"]), 2.0, 1.0)
    w *= np.where(txns["fraud_typology"] == "mule_fanin", 0.3, 1.0)
    w = w / w.sum()
    n_flip = int(0.02 * len(txns))
    flip = rng.choice(len(txns), size=n_flip, replace=False, p=w)
    txns.loc[flip, "is_fraud"] = 1 - txns.loc[flip, "is_fraud"]
    txns.loc[flip[txns.loc[flip, "is_fraud"].values == 1], "fraud_typology"] = "noise"

    return txns.sort_values("ts").reset_index(drop=True)


# --------------------------------------------------------------------------
# v2 channel semantics: agent float ledger, POS fees, USSD sessions,
# salary-day crediting, label lag
# --------------------------------------------------------------------------

# ₦50 electronic money transfer levy applies to inflows >= ₦10,000
EMT_LEVY_THRESHOLD = 10_000.0
EMT_LEVY_NGN = 50.0
# POS merchant service charge: 0.5% capped at ₦2,000
POS_CHARGE_PCT = 0.005
POS_CHARGE_CAP = 2_000.0


def _agent_fee(amount: float) -> float:
    """Typical agent-banking customer fee schedule."""
    if amount <= 5_000:
        return 50.0
    if amount <= 50_000:
        return 100.0
    return float(min(round(amount * 0.002, 2), 500.0))


def add_salary_credits(txns: pd.DataFrame, accts: pd.DataFrame,
                       rng: np.random.Generator) -> pd.DataFrame:
    """Per-account salary-day crediting + 3-day post-salary spend uplift.

    Salaried accounts receive one salary credit per month on their own
    salary_day (amount ~= monthly_income) from a small pool of employer
    accounts, and their spending in the 0-3 days after salary day is uplifted.
    """
    txns = txns.sort_values("ts").reset_index(drop=True)
    sal = accts[accts["salary_day"] > 0]
    if len(sal) == 0:
        txns["is_salary_credit"] = 0
        return txns
    employers = accts[accts["employment"] == "self_employed"]["customer_id"] \
        .head(20).to_numpy()
    if len(employers) == 0:
        employers = accts["customer_id"].head(20).to_numpy()
    t0, t1 = txns["ts"].min(), txns["ts"].max()
    months = pd.period_range(t0.to_period("M"), t1.to_period("M"), freq="M")
    cust = accts.set_index("customer_id")
    new_rows = []
    for cid, day, income in zip(sal["customer_id"], sal["salary_day"],
                                sal["monthly_income"]):
        for m in months:
            ts = m.start_time + pd.Timedelta(days=int(day) - 1,
                                             hours=int(rng.integers(8, 12)))
            if ts < t0 or ts > t1:
                continue
            emp = str(rng.choice(employers))
            new_rows.append(dict(
                txn_id=f"SAL{rng.integers(1e8):08d}", ts=ts,
                sender_id=emp, receiver_id=cid,
                amount_ngn=float(_kobo_round(income * rng.uniform(0.97, 1.03))),
                channel="nip", sender_bank=cust.loc[emp, "bank"],
                receiver_bank=cust.loc[cid, "bank"],
                sender_state=cust.loc[emp, "state"],
                receiver_state=cust.loc[cid, "state"],
                device_os="web_browser", hour=int(ts.hour), dow=int(ts.dayofweek),
                is_month_end=int(25 <= ts.day <= 31),
                is_market_day=int(ts.dayofweek in MARKET_DAYS),
                is_fraud=0, fraud_typology="legit", device_emulator=0,
                sim_swap_7d=0, new_device=0, is_salary_credit=1,
            ))
    txns["is_salary_credit"] = 0
    if new_rows:
        txns = pd.concat([txns, pd.DataFrame(new_rows)], ignore_index=True)
    # post-salary spend uplift: senders transacting 0-3 days after their
    # salary day spend more (per-account, replacing the global month-end proxy)
    sal_day = accts.set_index("customer_id")["salary_day"]
    sd = txns["sender_id"].map(sal_day).fillna(0).to_numpy()
    dom = txns["ts"].dt.day.to_numpy()
    since = (dom - sd) % 31
    uplift = (sd > 0) & (since <= 3)
    amt = txns["amount_ngn"].to_numpy(copy=True)
    amt[uplift] = _kobo_round(amt[uplift] * rng.uniform(1.2, 1.8, uplift.sum()))
    txns["amount_ngn"] = amt
    return txns.sort_values("ts").reset_index(drop=True)


def add_channel_semantics(txns: pd.DataFrame, accts: pd.DataFrame,
                          rng: np.random.Generator) -> pd.DataFrame:
    """POS fees + terminal/merchant IDs, agent float ledger, USSD sessions."""
    txns = txns.sort_values("ts").reset_index(drop=True)
    n = len(txns)
    ch = txns["channel"].to_numpy()

    # --- fees/charges ---------------------------------------------------------
    fee = np.zeros(n)
    amt = txns["amount_ngn"].to_numpy(dtype=float)
    pos = ch == "pos"
    fee[pos] = np.minimum(amt[pos] * POS_CHARGE_PCT, POS_CHARGE_CAP)
    fee[amt >= EMT_LEVY_THRESHOLD] += EMT_LEVY_NGN
    txns["fee_ngn"] = np.round(fee, 2)

    # POS terminal / merchant identifiers (shared pools -> repeats are normal)
    terminals = np.array([f"{rng.integers(1e7, 1e8):08d}" for _ in range(500)])
    merchants = np.array([f"M{rng.integers(1e5, 1e6):06d}" for _ in range(800)])
    txns["pos_terminal_id"] = ""
    txns["merchant_id"] = ""
    pidx = np.where(pos)[0]
    txns.loc[pidx, "pos_terminal_id"] = terminals[rng.integers(0, len(terminals), len(pidx))]
    txns.loc[pidx, "merchant_id"] = merchants[rng.integers(0, len(merchants), len(pidx))]

    # --- agent float ledger ----------------------------------------------------
    txns["agent_id"] = ""
    txns["cash_direction"] = ""
    txns["agent_float_after"] = np.nan
    agents = accts.loc[accts["is_agent"], "customer_id"].to_numpy()
    aidx = np.where(ch == "agent")[0]
    if len(agents) and len(aidx):
        assigned = agents[rng.integers(0, len(agents), len(aidx))]
        direction = rng.choice(["cash_in", "cash_out"], size=len(aidx), p=[0.52, 0.48])
        txns.loc[aidx, "agent_id"] = assigned
        txns.loc[aidx, "cash_direction"] = direction
        # agent fee replaces the POS charge schedule for agent txns
        txns.loc[aidx, "fee_ngn"] = [
            _agent_fee(a) + (EMT_LEVY_NGN if a >= EMT_LEVY_THRESHOLD else 0.0)
            for a in amt[aidx]]
        # per-agent float walk, in time order: cash-out fills the float,
        # cash-in drains it; depleted float triggers a rebalance reset.
        ledger = pd.DataFrame(dict(idx=aidx, agent=assigned,
                                   direction=direction, amt=amt[aidx],
                                   ts=txns["ts"].to_numpy()[aidx]))
        ledger = ledger.sort_values("ts")
        float_after = {}
        target = {}
        for row in ledger.itertuples():
            if row.agent not in float_after:
                target[row.agent] = float(_kobo_round(rng.uniform(500_000, 3_000_000)))
                float_after[row.agent] = target[row.agent]
            f = float_after[row.agent]
            f = f + row.amt if row.direction == "cash_out" else f - row.amt
            if f < 0.1 * target[row.agent]:  # rebalance: agent buys float
                f = target[row.agent] * rng.uniform(0.7, 1.0)
            float_after[row.agent] = f
            txns.loc[row.idx, "agent_float_after"] = round(f, 2)

    # --- USSD session semantics -------------------------------------------------
    txns["ussd_session_id"] = ""
    txns["session_duration_s"] = np.nan
    txns["ussd_step_count"] = np.nan
    txns["failed_pin_attempts"] = 0
    uidx = np.where(ch == "ussd")[0]
    if len(uidx):
        sub = txns.loc[uidx, ["ts", "sender_id", "is_fraud"]].sort_values("ts")
        sid, last = {}, {}
        sess_ids, durations, steps, pins = [], [], [], []
        for row in sub.itertuples():
            key = row.sender_id
            prev = last.get(key)
            if prev is not None and (row.ts - prev[0]).total_seconds() <= 180:
                # same short-TTL session burst: reuse session id, add steps
                s_id = prev[1]
                step = prev[2] + int(rng.integers(1, 3))
                last[key] = (row.ts, s_id, step)
            else:
                s_id = f"{rng.integers(1e11, 1e12):012d}"
                step = int(rng.integers(2, 6))
                last[key] = (row.ts, s_id, step)
            dur = float(np.clip(rng.lognormal(np.log(75), 0.5), 20, 600))
            pin = 0
            if rng.random() < (0.55 if row.is_fraud else 0.03):
                pin = int(rng.integers(1, 4))  # failed-PIN sequence before success
                dur *= 1 + 0.4 * pin  # retries extend the session
            sess_ids.append(s_id)
            durations.append(round(dur, 1))
            steps.append(step)
            pins.append(pin)
        txns.loc[sub.index, "ussd_session_id"] = sess_ids
        txns.loc[sub.index, "session_duration_s"] = durations
        txns.loc[sub.index, "ussd_step_count"] = steps
        txns.loc[sub.index, "failed_pin_attempts"] = pins
    return txns.sort_values("ts").reset_index(drop=True)


def add_label_lag(txns: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    """Label lag: fraud labels confirmed 7-30 days after the transaction.

    Mirrors real investigation pipelines (chargeback windows, customer
    disputes, analyst review). `label_available_at` is when the label became
    usable for training; legit labels are available immediately.
    """
    lag = pd.to_timedelta(rng.integers(7, 31, len(txns)), unit="D")
    txns["label_available_at"] = txns["ts"] + lag.where(
        txns["is_fraud"] == 1, pd.Timedelta(0))
    return txns


# --------------------------------------------------------------------------
# Feature engineering
# --------------------------------------------------------------------------

NUMERIC_FEATURES = [
    "log_amount", "hour", "dow", "is_month_end", "is_market_day",
    "amount_vs_sender_avg", "sender_txns_24h", "sender_unique_receivers_72h",
    "receiver_fanin_72h", "mins_since_last_txn", "device_emulator",
    "sim_swap_7d", "new_device", "cross_state", "cross_bank", "is_night",
]
CATEGORICAL_FEATURES = ["channel", "sender_bank", "receiver_bank",
                        "sender_state", "device_os"]


def add_behavioral_features(txns: pd.DataFrame) -> pd.DataFrame:
    """Windowed behavioural features (24h velocity, 72h fan-in/out)."""
    txns = txns.sort_values("ts").reset_index(drop=True)
    txns["log_amount"] = np.log1p(txns["amount_ngn"].astype(float))
    txns["is_night"] = ((txns["hour"] < 5) | (txns["hour"] >= 23)).astype(int)
    txns["cross_state"] = (txns["sender_state"] != txns["receiver_state"]).astype(int)
    txns["cross_bank"] = (txns["sender_bank"] != txns["receiver_bank"]).astype(int)

    sender_avg = txns.groupby("sender_id")["amount_ngn"].transform(
        lambda s: s.expanding().mean().shift().fillna(s.mean()))
    txns["amount_vs_sender_avg"] = (txns["amount_ngn"] / sender_avg.clip(lower=1)).clip(0, 50)

    ts = txns["ts"].astype("int64") // 10**9  # epoch seconds
    txns["_epoch"] = ts
    # 24h sender velocity via sorted two-pointer
    txns["sender_txns_24h"] = 0
    txns["mins_since_last_txn"] = 9999.0
    for sid, g in txns.groupby("sender_id", sort=False):
        e = g["_epoch"].to_numpy()
        cnt = np.arange(len(e)) - np.searchsorted(e, e - 86400, side="left")
        txns.loc[g.index, "sender_txns_24h"] = cnt
        gaps = np.diff(e, prepend=e[0] - 10**9) / 60.0
        txns.loc[g.index, "mins_since_last_txn"] = np.clip(gaps, 0, 9999)
    # 72h fan-out / fan-in
    txns["sender_unique_receivers_72h"] = 0
    txns["receiver_fanin_72h"] = 0
    win = 72 * 3600
    for sid, g in txns.groupby("sender_id", sort=False):
        e = g["_epoch"].to_numpy()
        r = g["receiver_id"].to_numpy()
        vals = np.zeros(len(e))
        for i in range(len(e)):
            lo = np.searchsorted(e, e[i] - win, side="left")
            vals[i] = len(np.unique(r[lo:i + 1]))
        txns.loc[g.index, "sender_unique_receivers_72h"] = vals
    for rid, g in txns.groupby("receiver_id", sort=False):
        e = g["_epoch"].to_numpy()
        txns.loc[g.index, "receiver_fanin_72h"] = (
            np.arange(len(e)) - np.searchsorted(e, e - win, side="left"))
    txns = txns.drop(columns=["_epoch"])
    return txns


# --------------------------------------------------------------------------
# Credit dataset
# --------------------------------------------------------------------------

def generate_credit(accts: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    """Credit-default dataset with bust-out behaviour baked in."""
    n = len(accts)
    loan_amt = _kobo_round(np.exp(rng.normal(12.6, 1.0, n)).clip(20_000, 40_000_000))
    term = rng.choice([3, 6, 12, 18, 24, 36], size=n, p=[.15, .2, .3, .15, .12, .08])
    purpose = rng.choice(["working_capital", "personal", "school_fees",
                          "medical", "agriculture", "device"], size=n,
                         p=[.3, .3, .1, .08, .12, .1])
    dti = np.clip(loan_amt / (accts["monthly_income"].to_numpy() * term) *
                  rng.uniform(0.5, 1.5, n), 0, 5)
    past_delinq = rng.poisson(0.4, n)
    bust_out = np.zeros(n, dtype=int)
    # bust-out rings: good bureau, max out, vanish
    bo_idx = rng.choice(n, size=n // 80, replace=False)
    bust_out[bo_idx] = 1
    bureau = accts["bureau_score"].to_numpy().astype(float)
    bureau[bo_idx] += rng.uniform(40, 90, len(bo_idx))  # groomed scores
    bureau = np.clip(bureau, 300, 850)
    logit = (
        -2.2
        + 2.4 * dti
        - 0.0045 * (bureau - 620)
        + 0.55 * past_delinq
        + 0.35 * (accts["employment"].isin(["unemployed", "student"])).astype(float)
        + 0.3 * (term > 24).astype(float)
        + 3.0 * bust_out
        + rng.normal(0, 0.6, n)
    )
    default = (rng.random(n) < 1 / (1 + np.exp(-logit))).astype(int)
    return pd.DataFrame(dict(
        customer_id=accts["customer_id"], age=accts["age"],
        employment=accts["employment"], state=accts["state"],
        bank=accts["bank"], monthly_income=accts["monthly_income"],
        bureau_score=bureau.round(0).astype(int), loan_amount_ngn=loan_amt,
        loan_term_months=term, purpose=purpose,
        dti=np.round(dti, 3), past_delinquencies=past_delinq,
        bust_out=bust_out, default=default,
    ))


# --------------------------------------------------------------------------
# Graph for GNN (mule detection)
# --------------------------------------------------------------------------

def build_graph(txns: pd.DataFrame, accts: pd.DataFrame,
                cutoff: pd.Timestamp | None = None):
    """Account->account directed graph + node features.

    `cutoff` restricts BOTH edges and node-feature aggregation to transactions
    at or before that timestamp. Training/validation graphs must be built with
    their split cutoff so node features never see future transactions
    (temporal leakage); the test graph uses the full window.
    """
    cid = accts["customer_id"].to_numpy()
    id2i = {c: i for i, c in enumerate(cid)}
    t = txns if cutoff is None else txns[txns["ts"] <= cutoff]
    src = t["sender_id"].map(id2i).to_numpy()
    dst = t["receiver_id"].map(id2i).to_numpy()
    edge_index = np.stack([src, dst])
    # node features from transaction behaviour (cutoff-masked)
    g = t.groupby("sender_id")["amount_ngn"]
    out_amt = g.sum().reindex(cid, fill_value=0).to_numpy()
    out_cnt = g.count().reindex(cid, fill_value=0).to_numpy()
    g2 = t.groupby("receiver_id")["amount_ngn"]
    in_amt = g2.sum().reindex(cid, fill_value=0).to_numpy()
    in_cnt = g2.count().reindex(cid, fill_value=0).to_numpy()
    uniq_in = t.groupby("receiver_id")["sender_id"].nunique().reindex(
        cid, fill_value=0).to_numpy()
    uniq_out = t.groupby("sender_id")["receiver_id"].nunique().reindex(
        cid, fill_value=0).to_numpy()
    X = np.stack([
        np.log1p(in_amt), np.log1p(out_amt), np.log1p(in_cnt),
        np.log1p(out_cnt), np.log1p(uniq_in), np.log1p(uniq_out),
        accts["bureau_score"].to_numpy() / 850.0,
        accts["age"].to_numpy() / 100.0,
        (accts["bank"].astype("category").cat.codes.to_numpy()) / 10.0,
        np.log1p(accts["monthly_income"].to_numpy()),
    ], axis=1).astype(np.float32)
    y = accts["is_mule"].astype(int).to_numpy()
    return X, edge_index.astype(np.int64), y


NODE_FEATURE_NAMES = [
    "log_in_amount", "log_out_amount", "log_in_count", "log_out_count",
    "log_unique_senders", "log_unique_receivers", "bureau_score_scaled",
    "age_scaled", "bank_code_scaled", "log_monthly_income",
]


# --------------------------------------------------------------------------
# Main: temporal split + parquet output
# --------------------------------------------------------------------------

def temporal_split(txns: pd.DataFrame, train_frac=0.7, val_frac=0.15):
    t = txns["ts"]
    t0, t1 = t.min(), t.max()
    cut1 = t0 + (t1 - t0) * train_frac
    cut2 = t0 + (t1 - t0) * (train_frac + val_frac)
    split = np.where(t <= cut1, "train", np.where(t <= cut2, "val", "test"))
    return split


def main(out_dir: str = "ml/data/generated", n_customers: int = 4000,
         n_txns: int = 60000, seed: int = SEED) -> dict:
    rng = np.random.default_rng(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    accts = generate_accounts(n_customers, rng)
    networks = _build_mule_networks(accts, rng, n_networks=10)
    txns = generate_transactions(accts, rng, n_txns=n_txns)
    txns = inject_fraud(txns, accts, networks, rng)
    txns = add_salary_credits(txns, accts, rng)
    txns = add_channel_semantics(txns, accts, rng)
    txns = add_label_lag(txns, rng)
    txns = add_behavioral_features(txns)
    credit = generate_credit(accts, rng)

    split = temporal_split(txns)
    txns["split"] = split

    # Split-aware graphs (leakage fix): train/val graphs aggregate only
    # transactions within their temporal window; test graph uses the full
    # window (evaluation-time information).
    t0, t1 = txns["ts"].min(), txns["ts"].max()
    cut_train = t0 + (t1 - t0) * 0.7
    cut_val = t0 + (t1 - t0) * 0.85
    X_tr, ei_tr, y = build_graph(txns, accts, cutoff=cut_train)
    X_va, ei_va, _ = build_graph(txns, accts, cutoff=cut_val)
    X_te, ei_te, _ = build_graph(txns, accts)

    accts.to_parquet(out / "accounts.parquet", index=False)
    txns.to_parquet(out / "transactions.parquet", index=False)
    credit.to_parquet(out / "credit.parquet", index=False)
    np.savez(out / "graph.npz",
             # backward-compatible keys point at the full-window (test) graph
             X=X_te, edge_index=ei_te, y=y,
             X_train=X_tr, edge_index_train=ei_tr,
             X_val=X_va, edge_index_val=ei_va,
             X_test=X_te, edge_index_test=ei_te,
             cut_train_ts=str(cut_train), cut_val_ts=str(cut_val),
             train_mask=_node_mask(accts, txns, "train"),
             val_mask=_node_mask(accts, txns, "val"),
             test_mask=_node_mask(accts, txns, "test"))
    meta = dict(
        seed=seed, dataset_version=DATASET_VERSION,
        n_customers=len(accts), n_txns=len(txns),
        fraud_rate=float(txns["is_fraud"].mean()),
        fraud_typologies=txns[txns["is_fraud"] == 1]["fraud_typology"]
        .value_counts().to_dict(),
        mule_accounts=int(accts["is_mule"].sum()),
        credit_default_rate=float(credit["default"].mean()),
        split_counts=pd.Series(split).value_counts().to_dict(),
        n_agents=int(accts["is_agent"].sum()),
        salary_credits=int(txns["is_salary_credit"].sum()),
        agent_txns=int((txns["channel"] == "agent").sum()),
        pos_txns=int((txns["channel"] == "pos").sum()),
        ussd_txns=int((txns["channel"] == "ussd").sum()),
        label_lag_days=[7, 30],
        provenance="synthetic",
    )
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def _node_mask(accts, txns, which):
    """Nodes active (as sender/receiver) up to the end of split `which`."""
    order = {"train": 0, "val": 1, "test": 2}
    cut = txns["ts"].max()
    if which != "test":
        fracs = {"train": 0.7, "val": 0.85}
        cut = txns["ts"].min() + (txns["ts"].max() - txns["ts"].min()) * fracs[which]
    active = set(txns.loc[txns["ts"] <= cut, "sender_id"]) | set(
        txns.loc[txns["ts"] <= cut, "receiver_id"])
    return accts["customer_id"].isin(active).to_numpy()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="ml/data/generated")
    ap.add_argument("--customers", type=int, default=4000)
    ap.add_argument("--txns", type=int, default=60000)
    ap.add_argument("--seed", type=int, default=SEED)
    a = ap.parse_args()
    m = main(a.out, a.customers, a.txns, a.seed)
    print(json.dumps(m, indent=2))
