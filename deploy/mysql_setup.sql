-- NDACS MySQL setup:  sudo mysql < deploy/mysql_setup.sql
-- Tables are created automatically by the application (SQLAlchemy) on first run.
CREATE DATABASE IF NOT EXISTS ndacs CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'ndacs'@'localhost' IDENTIFIED BY 'ndacs123';
GRANT ALL PRIVILEGES ON ndacs.* TO 'ndacs'@'localhost';
FLUSH PRIVILEGES;

-- For reference / your report, the schema the app creates:
-- alerts(id, ts, last_seen, src_ip, dst_ip, src_port, dst_port, protocol, label, confidence,
--        severity, source, action, count, explanation JSON-text, features JSON-text)
-- blocked_ips(id, ip, mode, reason, ts, expires, active)
-- honeypot_events(id, ts, src_ip, src_port, service, event, username, password, data)
-- traffic_stats(id, minute, flows, benign, malicious)
