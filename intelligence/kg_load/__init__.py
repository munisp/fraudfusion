"""KG loaders: ship the parquet KG store into graph servers, idempotently.

Both loaders MERGE on entity id / (src,dst,type) so re-running is safe.
"""
