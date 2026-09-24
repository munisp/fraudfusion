# Postgres role provisioning (run once per environment)

The k8s manifests reference per-service Postgres roles (`DB_USER` /
`DATABASE_URL` envs). Migrations create tables but intentionally do **not**
create roles (role passwords are environment secrets, not schema). Run this
script as a superuser (e.g. `postgres`) after cluster bootstrap and **before**
rolling out services, substituting real passwords from your secrets manager:

```sql
-- FraudFusion per-service database roles.
-- Principle of least privilege: services get CRUD on the application schema
-- only; DDL/migrations run as the separate `fraudfusion_migrator` role.
-- Passwords below are placeholders — generate per environment and store in
-- the corresponding k8s Secrets (detector-db, postgres-credentials, etc.).

-- Migrator/owner role: applies database/*.sql migrations at deploy time.
CREATE ROLE fraudfusion_migrator LOGIN PASSWORD 'CHANGE_ME_MIGRATOR';

-- Service roles referenced by deploy/kubernetes manifests.
CREATE ROLE aml_monitor                  LOGIN PASSWORD 'CHANGE_ME_AML';
CREATE ROLE advance_fee_fraud_detector   LOGIN PASSWORD 'CHANGE_ME_AFE';
CREATE ROLE crypto_fraud_detector        LOGIN PASSWORD 'CHANGE_ME_CRYPTO';
CREATE ROLE investment_fraud_detector    LOGIN PASSWORD 'CHANGE_ME_INV';
CREATE ROLE sim_swap_detector            LOGIN PASSWORD 'CHANGE_ME_SIM';
CREATE ROLE account_takeover_detector    LOGIN PASSWORD 'CHANGE_ME_ATO';
CREATE ROLE identity_theft_detector      LOGIN PASSWORD 'CHANGE_ME_ITD';
CREATE ROLE ledger_command               LOGIN PASSWORD 'CHANGE_ME_LEDGER';
CREATE ROLE chargeback_fraud_detector    LOGIN PASSWORD 'CHANGE_ME_CB';
CREATE ROLE insider_fraud_detector       LOGIN PASSWORD 'CHANGE_ME_INSIDER';
CREATE ROLE onboarding_service           LOGIN PASSWORD 'CHANGE_ME_ONB';
CREATE ROLE land_verification_service    LOGIN PASSWORD 'CHANGE_ME_LAND';
CREATE ROLE kyc_api                      LOGIN PASSWORD 'CHANGE_ME_KYC';

-- Database (created by cluster bootstrap / compose POSTGRES_DB).
-- CREATE DATABASE fraudfusion OWNER fraudfusion_migrator;

GRANT CONNECT ON DATABASE fraudfusion TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;

-- Apply AFTER migrations have created the tables (per-service CRUD).
GRANT USAGE ON SCHEMA public TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;
ALTER DEFAULT PRIVILEGES FOR ROLE fraudfusion_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;

-- Read-only regulator/audit access (pairs with the time-boxed, dual-control
-- grants provisioned via onboarding-service /api/v1/onboarding/admin/
-- regulator-access — that workflow records WHO gets access and WHEN it
-- expires; this role is the DB-side read-only principal it maps to).
CREATE ROLE fraudfusion_regulator_ro LOGIN PASSWORD 'CHANGE_ME_REGULATOR';
GRANT CONNECT ON DATABASE fraudfusion TO fraudfusion_regulator_ro;
GRANT USAGE ON SCHEMA public TO fraudfusion_regulator_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO fraudfusion_regulator_ro;
ALTER DEFAULT PRIVILEGES FOR ROLE fraudfusion_migrator IN SCHEMA public
    GRANT SELECT ON TABLES TO fraudfusion_regulator_ro;
```

## Notes

- **Order matters**: `GRANT ... ON ALL TABLES` covers only existing tables;
  the `ALTER DEFAULT PRIVILEGES` lines cover tables created by later
  migrations (run by `fraudfusion_migrator`).
- Detectors with runtime `EnsureSchema` (e.g. aml-monitor) additionally need
  `CREATE` on the schema for their own tables, or have the migrator pre-create
  them: `GRANT CREATE ON SCHEMA public TO aml_monitor;`
- Keycloak manages its own database (`keycloak` role + DB, see
  keycloak.yaml) and is intentionally separate.
- Rotate passwords by updating the role (`ALTER ROLE ... PASSWORD`) and the
  matching k8s Secret in the same change window.
