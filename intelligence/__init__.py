"""FraudFusion intelligence lane: knowledge-graph construction + analyst QA.

Packages:
  kg_pipeline — incremental KG construction from platform data (lakehouse
                parquet and/or Postgres), NDPA-pseudonymized, schema-versioned.
  kg_load     — idempotent loaders into FalkorDB and/or Neo4j.

Neither package fakes external dependencies: graph servers, Postgres drivers
and the optional cocoindex engine are detected at runtime and reported
honestly when unavailable.
"""
