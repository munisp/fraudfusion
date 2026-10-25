"""CLI runner for the Sedona geo-analytics jobs.

Used by the geo-analytics compose profile (deploy/geo-analytics.Dockerfile)
and runnable by hand anywhere pyspark + apache-sedona are installed:

    python -m geo_analytics mule-clusters \
        --events /data/events.parquet --out /data/out/mule_clusters \
        --eps-km 2.0 --min-samples 5

    python -m geo_analytics agent-offlocation \
        --events /data/agent_events.parquet --agents /data/agents.parquet \
        --out /data/out/agent_offlocation --radius-km 5.0

Fails honest: without pyspark/apache-sedona the underlying job raises a
RuntimeError naming the missing dependency — no silent partial results.
"""
from __future__ import annotations

import argparse
import json
import sys

from .sedona_jobs import agent_offlocation_rollup, mule_ring_geo_clusters


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="geo_analytics", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="job", required=True)

    mc = sub.add_parser("mule-clusters", help="DBSCAN geo-clustering of event coordinates")
    mc.add_argument("--events", required=True, help="parquet/json with subject_id, lat, lon")
    mc.add_argument("--out", required=True, help="output parquet path")
    mc.add_argument("--eps-km", type=float, default=2.0)
    mc.add_argument("--min-samples", type=int, default=5)

    ao = sub.add_parser("agent-offlocation", help="per-agent off-location share")
    ao.add_argument("--events", required=True, help="parquet/json with agent_id, lat, lon")
    ao.add_argument("--agents", required=True, help="parquet/json with agent_id, home_lat, home_lon")
    ao.add_argument("--out", required=True, help="output parquet path")
    ao.add_argument("--radius-km", type=float, default=5.0)

    args = parser.parse_args(argv)
    try:
        if args.job == "mule-clusters":
            result = mule_ring_geo_clusters(args.events, args.out,
                                            eps_km=args.eps_km,
                                            min_samples=args.min_samples)
        else:
            result = agent_offlocation_rollup(args.events, args.agents, args.out,
                                              radius_km=args.radius_km)
    except RuntimeError as exc:
        print(f"geo-analytics unavailable: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
