-- =====================================================================
-- PhishGuard - Phishing Attacks Detection System
-- MySQL 8.0 database schema
-- Run in MySQL Workbench, or:  mysql -u root -p < database/schema.sql
-- =====================================================================

CREATE DATABASE IF NOT EXISTS phishguard
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE phishguard;

-- ---------------------------A------------------------------------------
-- 1. Users (normal users and admins)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    full_name       VARCHAR(100)  NOT NULL,
    email           VARCHAR(150)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255)  NOT NULL,
    role            ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    is_active       TINYINT(1)    NOT NULL DEFAULT 1,
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login      DATETIME      NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 2. Machine learning model versions
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_versions (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    version         VARCHAR(30)   NOT NULL UNIQUE,
    algorithm       VARCHAR(80)   NOT NULL,
    accuracy        DECIMAL(6,4)  NULL,
    precision_score DECIMAL(6,4)  NULL,
    recall_score    DECIMAL(6,4)  NULL,
    f1_score        DECIMAL(6,4)  NULL,
    dataset_name    VARCHAR(150)  NULL,
    trained_at      DATETIME      NULL,
    registered_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 3. Scans (one row per URL checked)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT           NULL,             -- NULL = guest scan
    original_url    VARCHAR(2048) NOT NULL,
    normalized_url  VARCHAR(2048) NOT NULL,
    domain          VARCHAR(255)  NOT NULL,
    model_version   VARCHAR(30)   NULL,
    duration_ms     INT           NULL,
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scans_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scans_user (user_id),
    INDEX idx_scans_domain (domain)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 4. Scan signals (every check result that went into a scan)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_signals (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT           NOT NULL,
    source          ENUM('url', 'ml', 'threat', 'domain') NOT NULL,
    name            VARCHAR(100)  NOT NULL,
    status          ENUM('ok', 'warning', 'danger', 'info', 'unavailable') NOT NULL,
    points          INT           NOT NULL DEFAULT 0,
    detail          VARCHAR(500)  NULL,
    CONSTRAINT fk_signals_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    INDEX idx_signals_scan (scan_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 5. Risk results (final decision of the risk engine)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_results (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT           NOT NULL UNIQUE,
    risk_score      INT           NOT NULL,          -- 0 to 100
    risk_level      ENUM('Very Low', 'Low', 'Medium', 'High', 'Critical') NOT NULL,
    url_score       INT           NULL,
    ml_probability  DECIMAL(5,4)  NULL,
    domain_score    INT           NULL,
    threat_hit      TINYINT(1)    NOT NULL DEFAULT 0,
    summary         VARCHAR(500)  NOT NULL,
    CONSTRAINT fk_risk_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 6. Phishing reports submitted by users
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS phishing_reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT           NULL,
    url             VARCHAR(2048) NOT NULL,
    domain          VARCHAR(255)  NOT NULL,
    source_channel  ENUM('email', 'sms', 'whatsapp', 'social_media', 'website', 'other') NOT NULL DEFAULT 'other',
    description     VARCHAR(1000) NULL,
    status          ENUM('pending', 'confirmed', 'rejected') NOT NULL DEFAULT 'pending',
    reviewed_by     INT           NULL,
    reviewed_at     DATETIME      NULL,
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_reports_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_reports_reviewer
        FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_reports_status (status)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 7. Local blocklist (domains confirmed as phishing by an admin)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocklist (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    domain          VARCHAR(255)  NOT NULL UNIQUE,
    report_id       INT           NULL,
    added_by        INT           NULL,
    added_at        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_block_report
        FOREIGN KEY (report_id) REFERENCES phishing_reports(id) ON DELETE SET NULL,
    CONSTRAINT fk_block_admin
        FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 8. Audit log (important admin and security actions)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT           NULL,
    action          VARCHAR(100)  NOT NULL,
    detail          VARCHAR(500)  NULL,
    ip_address      VARCHAR(45)   NULL,
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;
