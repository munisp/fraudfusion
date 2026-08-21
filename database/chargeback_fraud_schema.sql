-- Chargeback Fraud Detection Schema
CREATE TABLE IF NOT EXISTS chargeback_transactions (id SERIAL PRIMARY KEY, transaction_id VARCHAR(255), customer_id VARCHAR(255), merchant_id VARCHAR(255), amount DECIMAL(15,2), currency VARCHAR(10), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS friendly_fraud_cases (id SERIAL PRIMARY KEY, transaction_id VARCHAR(255), customer_id VARCHAR(255), indicators TEXT[], confidence DECIMAL(5,2), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS chargeback_abuse_patterns (id SERIAL PRIMARY KEY, customer_id VARCHAR(255), chargeback_count INT, time_window INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS dispute_records (id SERIAL PRIMARY KEY, dispute_id VARCHAR(255), transaction_id VARCHAR(255), reason VARCHAR(255), status VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS chargeback_alerts (id SERIAL PRIMARY KEY, customer_id VARCHAR(255), alert_type VARCHAR(100), risk_level VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE VIEW high_chargeback_customers AS SELECT customer_id, COUNT(*) as chargeback_count FROM chargeback_transactions GROUP BY customer_id HAVING COUNT(*) > 5;
