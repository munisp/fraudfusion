"""Apache Sedona (Spark) geo-analytics jobs — platform-scale versions of
reference.py.

Fail-closed: pyspark / apache-sedona are optional dependencies. When they
are absent the job raises an honest RuntimeError naming exactly what is
missing — it never silently falls back to partial results at scale.

Eps honesty: Sedona's ST_ClusterDBSCAN takes eps in the geometry's own
units — degrees for EPSG:4326. We convert km -> degrees at the equator
(km / 111.32) and document the latitude distortion; for tighter work,
transform to a metric SRID first (ST_Transform to EPSG:3857 noted in the
job SQL comments).
"""
from __future__ import annotations

from typing import Any, Optional

KM_TO_DEG_AT_EQUATOR = 1.0 / 111.32


def _session(spark: Any = None) -> Any:
    """Return a Sedona-enabled SparkSession or raise an honest error."""
    if spark is not None:
        return spark
    try:
        from pyspark.sql import SparkSession
    except ImportError as exc:
        raise RuntimeError(
            "pyspark not installed: Sedona geo-analytics requires the "
            "analytics image (pip install pyspark apache-sedona); "
            "reference.py covers small extracts without Spark."
        ) from exc
    try:
        import sedona.spark  # noqa: F401  (registers Sedona SQL functions)
    except ImportError as exc:
        raise RuntimeError(
            "apache-sedona not installed: geo SQL functions (ST_Point, "
            "ST_ClusterDBSCAN, ST_DistanceSphere) are unavailable."
        ) from exc
    return (SparkSession.builder
            .appName("fraudfusion-geo-analytics")
            .getOrCreate())


def mule_ring_geo_clusters(events_path: str, out_path: str,
                           eps_km: float = 2.0, min_samples: int = 5,
                           spark: Any = None) -> dict[str, Any]:
    """DBSCAN over event coordinates at scale. Input: parquet/json with
    subject_id, lat, lon. Output: one row per flagged cluster."""
    spark = _session(spark)
    eps_deg = eps_km * KM_TO_DEG_AT_EQUATOR  # documented approximation
    df = spark.read.parquet(events_path) if events_path.endswith(".parquet") \
        else spark.read.json(events_path)
    df = df.where("lat IS NOT NULL AND lon IS NOT NULL")  # unresolved excluded honestly
    df.createOrReplaceTempView("events")
    clustered = spark.sql(f"""
        SELECT subject_id, lat, lon,
               ST_ClusterDBSCAN(ST_Point(CAST(lon AS double), CAST(lat AS double)),
                                {eps_deg}, {int(min_samples)}) OVER () AS cluster_id
        FROM events
    """)
    clustered.createOrReplaceTempView("clustered")
    flagged = spark.sql(f"""
        SELECT cluster_id,
               COUNT(DISTINCT subject_id) AS subject_count,
               COLLECT_SET(subject_id) AS distinct_subjects
        FROM clustered
        WHERE cluster_id >= 0
        GROUP BY cluster_id
        HAVING COUNT(DISTINCT subject_id) >= {int(min_samples)}
        ORDER BY subject_count DESC
    """)
    flagged.write.mode("overwrite").parquet(out_path)
    return {"status": "ok", "out": out_path, "eps_km": eps_km,
            "min_samples": min_samples,
            "note": "eps converted km->degrees at the equator; reproject to a "
                    "metric SRID for latitude-accurate clustering"}


def agent_offlocation_rollup(events_path: str, agents_path: str, out_path: str,
                             radius_km: float = 5.0, spark: Any = None) -> dict[str, Any]:
    """Per-agent off-location share at scale. events: agent_id, lat, lon;
    agents: agent_id, home_lat, home_lon. Uses ST_DistanceSphere (meters)."""
    spark = _session(spark)
    spark.read.parquet(events_path).createOrReplaceTempView("events") \
        if events_path.endswith(".parquet") \
        else spark.read.json(events_path).createOrReplaceTempView("events")
    spark.read.parquet(agents_path).createOrReplaceTempView("agents") \
        if agents_path.endswith(".parquet") \
        else spark.read.json(agents_path).createOrReplaceTempView("agents")
    spark.sql(f"""
        SELECT e.agent_id,
               COUNT(*) AS events,
               SUM(CASE WHEN ST_DistanceSphere(
                        ST_Point(CAST(e.lon AS double), CAST(e.lat AS double)),
                        ST_Point(CAST(a.home_lon AS double), CAST(a.home_lat AS double))
                    ) > {radius_km * 1000.0} THEN 1 ELSE 0 END) AS off_location
        FROM events e JOIN agents a ON e.agent_id = a.agent_id
        WHERE e.lat IS NOT NULL AND e.lon IS NOT NULL
        GROUP BY e.agent_id
    """).write.mode("overwrite").parquet(out_path)
    return {"status": "ok", "out": out_path, "radius_km": radius_km}
