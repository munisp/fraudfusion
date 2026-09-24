# FraudFusion MLOps wiring. Run from repo root: make -f mlops/Makefile <target>
PY ?= python

.PHONY: serve route drift perf export-demo analyze labels retrain smoke

# AML ML inference service on :8100 (used by services/go/aml-monitor)
serve:
	$(PY) mlops/serving/aml_service.py

# A/B model router on :8200 (champion/challenger from mlops/experiments/*.yaml)
route:
	$(PY) mlops/serving/model_router.py

# Demo lakehouse with 14 synthetic daily partitions
export-demo:
	$(PY) mlops/lakehouse/export.py --synthetic --days 14 --rows-per-day 500

# Drift: last 3 days vs the prior 7 days of the lakehouse
drift:
	$(PY) mlops/monitoring/drift.py \
	  --lakehouse-dir $${LAKEHOUSE_DIR:-mlops/data/lakehouse} \
	  --reference $$(date -d '10 days ago' +%F):$$(date -d '4 days ago' +%F) \
	  --current $$(date -d '3 days ago' +%F):$$(date +%F) \
	  --textfile mlops/data/drift.prom || test $$? -eq 2

# Rolling performance on labeled outcomes
perf:
	$(PY) mlops/monitoring/performance.py --window-days 7 \
	  --textfile mlops/data/performance.prom || test $$? -eq 2

# Experiment analysis over the router log
analyze:
	$(PY) mlops/experiments/analyze.py --log-dir mlops/data/router_log

# Full continuous-training loop
retrain:
	bash mlops/cron/retrain.sh

# End-to-end demo without a DB: export, drift, perf
smoke: export-demo drift perf
	@echo "smoke OK"
