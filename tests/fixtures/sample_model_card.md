# Sample Model Card — Test Fixture

This is a synthetic model card used for integration testing.
It intentionally addresses some controls and omits others.

## Model Overview

**Model name:** TestClassifier-v1  
**Version:** 1.0.0  
**Type:** Binary text classification  
**Intended use:** Detect policy violations in user-generated content  

## Intended Use and Limitations

This model is intended for internal content moderation use only.
It should not be used for high-stakes decisions affecting individuals
without human review. Known limitations include reduced accuracy on
non-English text and low-resource dialects.

## Risk Management

A risk assessment was conducted prior to deployment. Known risks include:
- False positives that incorrectly flag benign content
- Performance degradation on out-of-distribution inputs
- Potential for disparate impact across demographic groups

Risk tolerance thresholds are documented in the internal risk register.

## Fairness and Bias

Bias evaluations were performed across gender, age, and geographic categories.
Fairness metrics (demographic parity, equalised odds) are monitored monthly.
Disparate impact analysis showed acceptable performance across tested groups.

## Data Governance

Training data was sourced from internal logs with appropriate consent.
Personal data was pseudonymised prior to use. Data quality checks
were applied to remove duplicates and mislabelled examples.
Data governance practices follow the organisation's data policy.

## Security and Robustness

Adversarial robustness testing was performed using a red-team exercise.
The model showed resilience to common text perturbation attacks.
Security review completed by the InfoSec team on 2024-01-15.

## Transparency

This model card was prepared to enable transparent assessment by deployers.
The model's decision logic is not directly interpretable (black-box),
but SHAP explanations are available for individual predictions.
Users are notified when automated decisions are made using this model.

## Monitoring

Post-deployment monitoring is in place. Accuracy and fairness metrics
are tracked via a real-time dashboard. Drift alerts are configured
to trigger when performance degrades more than 5% from baseline.

## Incident Response

An incident response playbook exists for model-related incidents.
Escalation paths and contact information are documented.
The organisation has a feedback mechanism for users to report issues.

## Logging

Prediction logs are retained for 90 days for audit purposes.
Logs include input metadata, prediction scores, and timestamps.
No raw user content is stored in logs.
