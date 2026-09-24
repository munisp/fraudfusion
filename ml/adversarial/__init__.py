"""Adversarial robustness evaluation for the FraudFusion ML stack.

Currently covers evasion attacks (FGSM / PGD) against the fraud_net tabular
classifier with feature-space plausibility constraints, plus post-defense
re-evaluation. Uses the Adversarial Robustness Toolbox (ART) when installed;
otherwise falls back to a hand-rolled torch implementation (which is also the
reference implementation for constrained, per-feature-bounded attacks).
"""
