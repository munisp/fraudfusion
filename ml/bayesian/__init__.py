"""Bayesian inference lane: dependency-light MCMC + fitted posterior artifacts.

Modules:
  mcmc                 Metropolis-Hastings / NUTS-lite sampler, diagnostics
  fraud_calibration    Bayesian logistic calibration of fraud_net scores
  mule_ring_posterior  posterior over "account in active mule ring"
  insider_risk         hierarchical (partial pooling) insider-event rates
"""
