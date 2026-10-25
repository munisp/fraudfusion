# Apache Sedona geo-analytics runner for FraudFusion.
#
# Batch (not long-running): the container runs one job and exits.
#   docker compose -f deploy/docker-compose.platform.yml --profile geo-analytics \
#     run --rm geo-analytics mule-clusters \
#       --events /data/events.parquet --out /data/out/mule_clusters
#
# Base image: official Apache Sedona Docker image (Spark + Sedona SQL
# functions pre-registered). If the registry is unreachable, any
# pyspark+apache-sedona environment works identically:
#   pip install pyspark apache-sedona && python -m geo_analytics ...
FROM apache/sedona:1.7.1

USER root
WORKDIR /opt/fraudfusion
COPY intelligence/geo_analytics /opt/fraudfusion/geo_analytics

ENTRYPOINT ["python", "-m", "geo_analytics"]
