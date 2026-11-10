-- ============================================================
-- DATABASE: ai_securauth
-- Sistem Deteksi Pembajakan Akun & Autentikasi Berbasis Risiko
-- AI-Based Risk Authentication & Account Takeover Defense
-- Mata Kuliah: AI for Security (PjBL)
-- ============================================================

CREATE DATABASE IF NOT EXISTS `ai_securauth`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `ai_securauth`;

-- ============================================================
-- TABEL 1: users (Pengguna Sistem / Admin & Analis)
-- ============================================================
CREATE TABLE IF NOT EXISTS `users` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`    VARCHAR(60)  NOT NULL UNIQUE,
  `password`    VARCHAR(255) NOT NULL COMMENT 'bcrypt hashed',
  `nama`        VARCHAR(120) NOT NULL,
  `role`        ENUM('soc_analyst','security_engineer','auditor') NOT NULL DEFAULT 'soc_analyst',
  `email`       VARCHAR(150) DEFAULT NULL,
  `is_active`   TINYINT(1)   NOT NULL DEFAULT 1,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login`  DATETIME     DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Akun pengguna internal sistem';

-- ============================================================
-- TABEL 2: login_logs (Rekaman Setiap Percobaan Login)
-- ============================================================
CREATE TABLE IF NOT EXISTS `login_logs` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `timestamp`       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `user_id_target`  VARCHAR(80)     NOT NULL COMMENT 'Username/User-ID yang mencoba login ke layanan',
  `ip_address`      VARCHAR(45)     NOT NULL,
  `asn`             VARCHAR(80)     DEFAULT NULL COMMENT 'Autonomous System Number',
  `country`         VARCHAR(80)     DEFAULT NULL,
  `region`          VARCHAR(80)     DEFAULT NULL,
  `city`            VARCHAR(80)     DEFAULT NULL,
  `latitude`        DECIMAL(9,6)    DEFAULT NULL,
  `longitude`       DECIMAL(9,6)    DEFAULT NULL,
  `device_type`     ENUM('desktop','mobile','tablet','unknown') NOT NULL DEFAULT 'unknown',
  `os`              VARCHAR(60)     DEFAULT NULL,
  `browser`         VARCHAR(60)     DEFAULT NULL,
  `rtt_ms`          INT             DEFAULT NULL COMMENT 'Round-Trip Time dalam milidetik',
  `is_attack_ip`    TINYINT(1)      NOT NULL DEFAULT 0 COMMENT '1 = IP terdaftar sebagai penyerang',
  `login_success`   TINYINT(1)      NOT NULL DEFAULT 0 COMMENT '1 = Login berhasil',
  `risk_score`      DECIMAL(5,2)    DEFAULT NULL COMMENT 'Skor risiko AI (0.00 - 100.00)',
  `risk_level`      ENUM('low','medium','high') DEFAULT NULL,
  `ai_decision`     ENUM('allow','challenge_mfa','block') DEFAULT NULL,
  `model_used`      VARCHAR(40)     DEFAULT NULL COMMENT 'XGBoost / RandomForest',
  `is_account_takeover` TINYINT(1)  NOT NULL DEFAULT 0 COMMENT 'Label ground-truth ATO',
  PRIMARY KEY (`id`),
  KEY `idx_timestamp`   (`timestamp`),
  KEY `idx_ip`          (`ip_address`),
  KEY `idx_decision`    (`ai_decision`),
  KEY `idx_risk_level`  (`risk_level`),
  KEY `idx_ato`         (`is_account_takeover`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Log seluruh percobaan login (live feed)';

-- ============================================================
-- TABEL 3: incidents (Tiket Insiden Account Takeover)
-- ============================================================
CREATE TABLE IF NOT EXISTS `incidents` (
  `id`              INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `log_id`          BIGINT UNSIGNED NOT NULL COMMENT 'FK ke login_logs.id',
  `title`           VARCHAR(200)  NOT NULL,
  `severity`        ENUM('critical','high','medium','low') NOT NULL DEFAULT 'high',
  `status`          ENUM('open','investigating','resolved','false_positive') NOT NULL DEFAULT 'open',
  `assigned_to`     INT UNSIGNED  DEFAULT NULL COMMENT 'FK ke users.id',
  `description`     TEXT          DEFAULT NULL,
  `behavioral_note` TEXT          DEFAULT NULL COMMENT 'Catatan behavioral drift / impossible travel',
  `created_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `resolved_at`     DATETIME      DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_status`   (`status`),
  KEY `idx_severity` (`severity`),
  CONSTRAINT `fk_incident_log`  FOREIGN KEY (`log_id`)       REFERENCES `login_logs`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_incident_user` FOREIGN KEY (`assigned_to`)  REFERENCES `users`(`id`)      ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Tiket insiden Account Takeover';

-- ============================================================
-- TABEL 4: incident_actions (Log Tindakan atas Insiden)
-- ============================================================
CREATE TABLE IF NOT EXISTS `incident_actions` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `incident_id` INT UNSIGNED NOT NULL,
  `action_type` ENUM('revoke_session','force_reset_password','lock_account','unlock_account','add_note','status_change') NOT NULL,
  `note`        TEXT DEFAULT NULL,
  `executed_by` INT UNSIGNED DEFAULT NULL COMMENT 'FK ke users.id',
  `executed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_incident` (`incident_id`),
  CONSTRAINT `fk_action_incident` FOREIGN KEY (`incident_id`) REFERENCES `incidents`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_action_user`     FOREIGN KEY (`executed_by`) REFERENCES `users`(`id`)     ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Riwayat tindakan mitigasi per insiden';

-- ============================================================
-- TABEL 5: ip_reputation (Whitelist & Blacklist IP/ASN)
-- ============================================================
CREATE TABLE IF NOT EXISTS `ip_reputation` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `type`        ENUM('whitelist','blacklist') NOT NULL,
  `entry_value` VARCHAR(100) NOT NULL COMMENT 'IP, subnet CIDR, atau ASN',
  `entry_type`  ENUM('ip','subnet','asn') NOT NULL DEFAULT 'ip',
  `reason`      VARCHAR(255) DEFAULT NULL,
  `added_by`    INT UNSIGNED DEFAULT NULL COMMENT 'FK ke users.id',
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_entry` (`type`, `entry_value`),
  CONSTRAINT `fk_rep_user` FOREIGN KEY (`added_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Daftar whitelist dan blacklist IP/ASN';

-- ============================================================
-- TABEL 6: policy_thresholds (Konfigurasi Ambang Batas Risiko)
-- ============================================================
CREATE TABLE IF NOT EXISTS `policy_thresholds` (
  `id`                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `mfa_threshold`        DECIMAL(5,2) NOT NULL DEFAULT 30.00 COMMENT 'Batas bawah pemicu MFA (%)',
  `block_threshold`      DECIMAL(5,2) NOT NULL DEFAULT 70.00 COMMENT 'Batas pemicu BLOCK (%)',
  `operation_mode`       ENUM('passive','active') NOT NULL DEFAULT 'active',
  `active_model`         ENUM('xgboost','random_forest') NOT NULL DEFAULT 'xgboost',
  `updated_by`           INT UNSIGNED DEFAULT NULL,
  `updated_at`           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_policy_user` FOREIGN KEY (`updated_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Konfigurasi ambang batas risiko AI';

-- ============================================================
-- TABEL 7: policy_rules (Aturan Heuristik Kustom)
-- ============================================================
CREATE TABLE IF NOT EXISTS `policy_rules` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `rule_name`   VARCHAR(120) NOT NULL,
  `condition_field` VARCHAR(60) NOT NULL COMMENT 'Contoh: is_attack_ip, country, rtt_ms',
  `condition_op`    VARCHAR(20) NOT NULL COMMENT 'Contoh: equals, greater_than, in',
  `condition_value` VARCHAR(200) NOT NULL,
  `action`      ENUM('block','allow','require_mfa','adjust_score') NOT NULL,
  `score_delta` DECIMAL(5,2) DEFAULT NULL COMMENT 'Nilai perubahan skor (untuk adjust_score)',
  `is_active`   TINYINT(1)   NOT NULL DEFAULT 1,
  `created_by`  INT UNSIGNED DEFAULT NULL,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_rule_user` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Aturan keamanan logika kustom (rule-based override)';

-- ============================================================
-- TABEL 8: model_metrics (Hasil Evaluasi Model ML)
-- ============================================================
CREATE TABLE IF NOT EXISTS `model_metrics` (
  `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `model_name`   VARCHAR(80)  NOT NULL COMMENT 'XGBoost / Random Forest',
  `version`      VARCHAR(20)  NOT NULL DEFAULT 'v1.0',
  `accuracy`     DECIMAL(6,4) DEFAULT NULL,
  `precision_score` DECIMAL(6,4) DEFAULT NULL,
  `recall`       DECIMAL(6,4) DEFAULT NULL,
  `f1_score`     DECIMAL(6,4) DEFAULT NULL,
  `roc_auc`      DECIMAL(6,4) DEFAULT NULL,
  `tp`           INT DEFAULT NULL COMMENT 'True Positive',
  `fp`           INT DEFAULT NULL COMMENT 'False Positive',
  `tn`           INT DEFAULT NULL COMMENT 'True Negative',
  `fn`           INT DEFAULT NULL COMMENT 'False Negative',
  `train_samples` INT DEFAULT NULL,
  `test_samples`  INT DEFAULT NULL,
  `trained_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_active`    TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = model yang sedang digunakan',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Metrik evaluasi model Machine Learning';

-- ============================================================
-- TABEL 9: audit_logs (Jejak Audit Aktivitas Staf Sistem)
-- ============================================================
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`     INT UNSIGNED    DEFAULT NULL,
  `action`      VARCHAR(100)    NOT NULL COMMENT 'Contoh: login, change_threshold, add_blacklist',
  `target_type` VARCHAR(60)     DEFAULT NULL COMMENT 'Contoh: incident, policy, ip_reputation',
  `target_id`   VARCHAR(40)     DEFAULT NULL,
  `detail`      TEXT            DEFAULT NULL,
  `ip_address`  VARCHAR(45)     DEFAULT NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user`   (`user_id`),
  KEY `idx_action` (`action`),
  KEY `idx_time`   (`created_at`),
  CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Audit trail seluruh aktivitas pengguna sistem';

-- ============================================================
-- DATA AWAL (SEED DATA)
-- ============================================================

-- Admin default: password = Admin@123 (scrypt hash - Werkzeug 3.x compatible)
INSERT INTO `users` (`username`, `password`, `nama`, `role`, `email`) VALUES
('admin',    'scrypt:32768:8:1$bTh0Tyg9IOcL6hvX$e9f7985a90176a90cc1a0765d33167a5f28592887d30a0f2285393c1bb33394c47ce224b2b65e718b95baf1ba4692eacd16793855c73f5e4a6d61f6863ed3132', 'Administrator',    'security_engineer', 'admin@securauth.local'),
('analyst1', 'scrypt:32768:8:1$bzMY2NzMeWFLpQtx$50d4e022d4d998d078d0807c627d0420dfd92198b50d6a173ef45bb42725ed4320a09c4beeab78e39467e0fa99e5d26fb66aec0ca352e8d0ef9b8aa94bada1e8', 'Analis SOC 1',     'soc_analyst',       'analyst1@securauth.local'),
('auditor1', 'scrypt:32768:8:1$WFimkijO1zjOYTzM$42dac8eb8c1ae279418a7f7b4f27553cac4885c411dc4710decfcd90cac0708e18e04d7e41c63b5082221f24a540919b08592104eb026e1e594aa592a694dc8d', 'Auditor Keamanan', 'auditor',           'auditor1@securauth.local');

-- Konfigurasi default ambang batas
INSERT INTO `policy_thresholds` (`mfa_threshold`, `block_threshold`, `operation_mode`, `active_model`, `updated_by`) 
VALUES (30.00, 70.00, 'active', 'xgboost', 1);

-- Contoh aturan kustom bawaan
INSERT INTO `policy_rules` (`rule_name`, `condition_field`, `condition_op`, `condition_value`, `action`, `score_delta`, `is_active`, `created_by`) VALUES
('Block Known Attack IPs Immediately',  'is_attack_ip', 'equals',       '1',    'block',        NULL,  1, 1),
('High RTT Penalty',                    'rtt_ms',        'greater_than', '2000', 'adjust_score', 20.00, 1, 1),
('Whitelist Internal Office Range',     'asn',           'equals',       'AS_INTERNAL', 'allow', NULL,  0, 1);

-- Contoh beberapa IP di blacklist
INSERT INTO `ip_reputation` (`type`, `entry_value`, `entry_type`, `reason`, `added_by`) VALUES
('blacklist', '185.220.101.0/24', 'subnet', 'Tor exit node range - known attacker',       1),
('blacklist', '45.148.10.52',     'ip',     'Brute-force detected - 500+ attempts/hour',  1),
('blacklist', 'AS62748',          'asn',    'Malicious ASN flagged by threat intelligence',1),
('whitelist', '192.168.0.0/16',   'subnet', 'Internal network - office range',            1);

-- Metrik evaluasi kedua model (data dari penelitian Minggu 5 & 6)
INSERT INTO `model_metrics` (`model_name`, `version`, `accuracy`, `precision_score`, `recall`, `f1_score`, `roc_auc`, `tp`, `fp`, `tn`, `fn`, `train_samples`, `test_samples`, `is_active`) VALUES
('Random Forest', 'v1.0', 0.9612, 0.7340, 0.7850, 0.7586, 0.9420, 1962, 710, 17280, 538, 80000, 20490, 0),
('XGBoost',       'v1.0', 0.9684, 0.7820, 0.8310, 0.8057, 0.9671, 2077, 579, 17411, 423, 80000, 20490, 1);

-- Sample data login_logs (20 baris representatif)
INSERT INTO `login_logs` (`timestamp`, `user_id_target`, `ip_address`, `asn`, `country`, `region`, `city`, `latitude`, `longitude`, `device_type`, `os`, `browser`, `rtt_ms`, `is_attack_ip`, `login_success`, `risk_score`, `risk_level`, `ai_decision`, `model_used`, `is_account_takeover`) VALUES
('2026-11-10 06:01:12', 'user_1234', '203.0.113.10',  'AS9311',  'Indonesia', 'DKI Jakarta',    'Jakarta',   -6.2088,  106.8456, 'desktop', 'Windows 11', 'Chrome 128',    45,   0, 1,  12.50, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 06:03:44', 'user_5678', '185.220.101.5', 'AS62748', 'Russia',    'Moscow Oblast',  'Moscow',    55.7558,   37.6173, 'desktop', 'Linux',      'Firefox 119',   3100, 1, 0,  97.80, 'high',   'block',         'XGBoost', 1),
('2026-11-10 06:08:19', 'user_2234', '1.179.147.2',   'AS23969', 'Thailand',  'Bangkok',        'Bangkok',   13.7563,  100.5018, 'mobile',  'Android 14', 'Chrome Mobile', 180,  0, 1,  28.40, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 06:12:05', 'user_9901', '45.148.10.52',  'AS59432', 'Germany',   'Bavaria',        'Munich',    48.1351,   11.5820, 'desktop', 'Windows 10', 'Edge 118',      2800, 1, 0,  94.60, 'high',   'block',         'XGBoost', 1),
('2026-11-10 06:15:33', 'user_3312', '36.68.172.4',   'AS17974', 'Indonesia', 'Jawa Timur',     'Surabaya',  -7.2575,  112.7521, 'mobile',  'iOS 17',     'Safari',         60,  0, 1,  18.20, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 06:18:47', 'user_4421', '91.108.4.100',  'AS62014', 'Netherlands','North Holland', 'Amsterdam', 52.3676,    4.9041, 'desktop', 'macOS 14',   'Safari 17',    1650, 0, 0,  51.30, 'medium', 'challenge_mfa', 'XGBoost', 0),
('2026-11-10 06:22:14', 'user_1234', '192.168.1.100', 'AS_INT',  'Indonesia', 'DKI Jakarta',    'Jakarta',   -6.2088,  106.8456, 'desktop', 'Windows 11', 'Chrome 128',     12,  0, 1,   5.10, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 06:28:55', 'user_7731', '5.188.86.172',  'AS35624', 'Ukraine',   'Kyiv City',      'Kyiv',      50.4501,   30.5234, 'desktop', 'Windows 7',  'IE 11',         3800, 1, 0,  99.10, 'high',   'block',         'XGBoost', 1),
('2026-11-10 06:33:08', 'user_6610', '114.4.180.22',  'AS17622', 'Indonesia', 'Jawa Barat',     'Bandung',   -6.9175,  107.6191, 'mobile',  'Android 13', 'Chrome Mobile',  95,  0, 1,  22.00, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 06:40:21', 'user_8820', '104.21.33.14',  'AS13335', 'USA',       'California',     'Los Angeles',34.0522,-118.2437, 'desktop', 'Windows 11', 'Chrome 128',   1200, 0, 0,  47.80, 'medium', 'challenge_mfa', 'XGBoost', 0),
('2026-11-10 06:44:33', 'user_5512', '36.68.200.10',  'AS17974', 'Indonesia', 'DKI Jakarta',    'Jakarta',   -6.2088,  106.8456, 'tablet',  'iOS 16',     'Safari',         70,  0, 1,  14.50, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 06:50:11', 'user_2234', '109.70.100.14', 'AS208323','Poland',    'Masovian',       'Warsaw',    52.2297,   21.0122, 'desktop', 'Windows 10', 'Firefox 119',   4200, 1, 0,  98.50, 'high',   'block',         'XGBoost', 1),
('2026-11-10 07:01:04', 'user_3312', '36.68.172.4',   'AS17974', 'Indonesia', 'Jawa Timur',     'Surabaya',  -7.2575,  112.7521, 'mobile',  'iOS 17',     'Safari',         55,  0, 1,  13.00, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 07:05:49', 'user_7799', '192.0.2.80',    'AS7018',  'USA',       'Texas',          'Houston',   29.7604,  -95.3698, 'desktop', 'macOS 13',   'Chrome 128',    980,  0, 1,  39.60, 'medium', 'challenge_mfa', 'XGBoost', 0),
('2026-11-10 07:10:17', 'user_4421', '91.108.4.101',  'AS62014', 'Netherlands','North Holland', 'Amsterdam', 52.3676,    4.9041, 'desktop', 'macOS 14',   'Safari 17',    1550, 0, 1,  44.20, 'medium', 'challenge_mfa', 'XGBoost', 0),
('2026-11-10 07:15:33', 'user_0011', '203.0.113.42',  'AS9311',  'Indonesia', 'DKI Jakarta',    'Jakarta',   -6.2088,  106.8456, 'desktop', 'Windows 11', 'Chrome 128',     38,  0, 1,  10.80, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 07:22:40', 'user_6618', '45.148.10.60',  'AS59432', 'Germany',   'Berlin',         'Berlin',    52.5200,   13.4050, 'desktop', 'Linux',      'Firefox 119',   3300, 1, 0,  96.70, 'high',   'block',         'XGBoost', 1),
('2026-11-10 07:30:55', 'user_1122', '114.4.180.80',  'AS17622', 'Indonesia', 'Jawa Barat',     'Bandung',   -6.9175,  107.6191, 'mobile',  'Android 14', 'Chrome Mobile',  88,  0, 1,  17.30, 'low',    'allow',         'XGBoost', 0),
('2026-11-10 07:35:12', 'user_9901', '188.165.208.9', 'AS16276', 'France',    'Île-de-France',  'Paris',     48.8566,    2.3522, 'desktop', 'Windows 11', 'Edge 118',      2100, 0, 0,  58.90, 'medium', 'challenge_mfa', 'XGBoost', 0),
('2026-11-10 07:42:08', 'user_5678', '5.188.86.200',  'AS35624', 'Ukraine',   'Kyiv City',      'Kyiv',      50.4501,   30.5234, 'desktop', 'Windows 7',  'IE 11',         4100, 1, 0,  99.80, 'high',   'block',         'XGBoost', 1);

-- Insiden dari 5 login high-risk
INSERT INTO `incidents` (`log_id`, `title`, `severity`, `status`, `assigned_to`, `description`, `behavioral_note`) VALUES
(2,  'ATO Attempt - Tor Exit Node Russia',       'critical', 'investigating', 1, 'Login dari IP Tor exit node Rusia. RTT 3100ms. IP terdaftar di threat feed.', 'Perangkat tidak dikenal. Lokasi berbeda 8.000 km dari login terakhir user (Jakarta). Kemungkinan Impossible Travel.'),
(4,  'ATO Attempt - Known Attacker IP Germany',  'high',     'open',          2, 'IP 45.148.10.52 terdaftar di blacklist. 500+ percobaan brute-force terdeteksi.', 'OS dan browser berbeda dari profil normal pengguna.'),
(8,  'ATO Attempt - Suspicious Login Ukraine',   'critical', 'resolved',      1, 'Login dari IP Ukraina yang masuk blacklist ASN. Sesi aktif langsung dicabut.', 'Jarak lokasi 7.600 km dari login sah terakhir dalam 2 jam — mustahil secara fisik.'),
(12, 'ATO Attempt - Attack IP Poland',           'high',     'open',          2, 'IP masuk database penyerang. RTT sangat tinggi (4200ms) mengindikasikan proxy.', NULL),
(17, 'ATO Attempt - Blacklisted ASN Germany',    'high',     'investigating', 1, 'ASN62014 diblokir. Login gagal. Kemungkinan credential stuffing.', 'Browser lawas (IE11) tidak sesuai profil device pengguna.');

-- Tindakan atas insiden #3 (resolved)
INSERT INTO `incident_actions` (`incident_id`, `action_type`, `note`, `executed_by`) VALUES
(3, 'revoke_session',        'Sesi aktif user_5678 dicabut segera.',       1),
(3, 'force_reset_password',  'Tautan reset password dikirim ke email.',     1),
(3, 'lock_account',          'Akun dikunci sementara 24 jam.',              1),
(3, 'status_change',         'Status tiket diubah ke: Resolved.',           1);

-- Contoh audit log
INSERT INTO `audit_logs` (`user_id`, `action`, `target_type`, `target_id`, `detail`, `ip_address`) VALUES
(1, 'login',               'users',          '1',  'Login berhasil oleh admin.',          '192.168.1.100'),
(1, 'add_blacklist',       'ip_reputation',  '1',  'Tambah blacklist: 185.220.101.0/24', '192.168.1.100'),
(1, 'change_threshold',    'policy_thresholds','1', 'MFA: 30%, Block: 70%',              '192.168.1.100'),
(2, 'login',               'users',          '2',  'Login berhasil oleh analyst1.',       '192.168.1.101'),
(2, 'update_incident',     'incidents',      '2',  'Insiden #2 diassign ke analyst1.',    '192.168.1.101'),
(1, 'switch_model',        'policy_thresholds','1', 'Model aktif diubah ke XGBoost.',    '192.168.1.100');

