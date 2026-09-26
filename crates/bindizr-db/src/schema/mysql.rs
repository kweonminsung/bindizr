//! MySQL DDL.
//!
//! Names compare under `utf8mb4_bin`, and `idx_records_zone_name` takes a
//! 255-character prefix: a utf8mb4 VARCHAR(1024) exceeds InnoDB's 3,072-byte
//! key. Record values are MEDIUMTEXT: a TXT rendered with `\DDD` escapes can
//! quadruple its 65,535-octet RDATA past what TEXT holds.

/// Return the statements that create the application schema.
pub(crate) fn table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_policies (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            algorithm INT NOT NULL,
            denial VARCHAR(8) NOT NULL,
            split_keys BOOLEAN NOT NULL DEFAULT FALSE,
            signature_validity_days INT NOT NULL,
            signature_refresh_days INT NOT NULL,
            zsk_lifetime_days INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) COLLATE utf8mb4_bin UNIQUE NOT NULL,
            mname VARCHAR(255) NOT NULL,
            rname VARCHAR(255) NOT NULL,
            default_ttl INT NOT NULL,
            serial INT NOT NULL,
            refresh INT NOT NULL DEFAULT 300,
            retry INT NOT NULL DEFAULT 60,
            expire INT NOT NULL DEFAULT 3600000,
            minimum_ttl INT NOT NULL DEFAULT 86400,
            dnssec_policy_id INT NULL,
            parent_ns_addrs VARCHAR(1024) NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            description VARCHAR(255),
            created_at DATETIME NOT NULL,
            FOREIGN KEY (dnssec_policy_id) REFERENCES dnssec_policies(id),
            INDEX idx_zones_dnssec_policy (dnssec_policy_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            value MEDIUMTEXT NOT NULL,
            display_value MEDIUMTEXT NOT NULL,
            ttl INT NOT NULL,
            priority INT,
            created_at DATETIME NOT NULL,
            zone_id INT NOT NULL,
            CHECK ((record_type IN ('MX', 'SRV')) = (priority IS NOT NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_records_zone_name (zone_id, name(255)),
            INDEX idx_records_zone_type (zone_id, record_type)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_journal (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            serial INT NOT NULL,
            operation VARCHAR(10) NOT NULL,
            record_name VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            record_value MEDIUMTEXT,
            record_rdata BLOB,
            record_ttl INT NOT NULL,
            record_priority INT,
            derived BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL,
            CHECK ((derived = TRUE AND record_value IS NULL AND record_rdata IS NOT NULL)
                OR (derived = FALSE AND record_value IS NOT NULL AND record_rdata IS NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_zone_serial (zone_id, serial),
            INDEX idx_zone_journal_created (created_at)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_versions (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            serial INT NOT NULL,
            mname TEXT NOT NULL,
            rname TEXT NOT NULL,
            default_ttl INT NOT NULL,
            refresh INT NOT NULL,
            retry INT NOT NULL,
            expire INT NOT NULL,
            minimum_ttl INT NOT NULL,
            change_source VARCHAR(16) NOT NULL,
            changed_by VARCHAR(255),
            created_at DATETIME NOT NULL,
            UNIQUE KEY uq_zone_serial (zone_id, serial),
            INDEX idx_zone_versions_created (created_at),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            token VARCHAR(64) UNIQUE NOT NULL,
            description VARCHAR(255),
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL,
            expires_at DATETIME,
            last_used_at DATETIME
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS catalog_zones (
            name VARCHAR(255) PRIMARY KEY,
            digest VARCHAR(64) NOT NULL,
            serial INT NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_withdrawals (
            zone_id INT PRIMARY KEY,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS tsig_keys (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) COLLATE utf8mb4_bin UNIQUE NOT NULL,
            algorithm VARCHAR(32) NOT NULL,
            secret VARCHAR(255) NOT NULL,
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS secondaries (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) COLLATE utf8mb4_bin UNIQUE NOT NULL,
            address VARCHAR(255) COLLATE utf8mb4_bin UNIQUE NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            notify_tsig_key_id INT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (notify_tsig_key_id) REFERENCES tsig_keys(id),
            INDEX idx_secondaries_notify_key (notify_tsig_key_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS tsig_grants (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            tsig_key_id INT NOT NULL,
            record_name_pattern VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            can_write BOOLEAN NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys(id),
            INDEX idx_tsig_grants_zone (zone_id),
            INDEX idx_tsig_grants_key (tsig_key_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS token_grants (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            api_token_id INT NOT NULL,
            record_name_pattern VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            can_write BOOLEAN NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (api_token_id) REFERENCES api_tokens(id) ON DELETE CASCADE,
            INDEX idx_token_grants_zone (zone_id),
            INDEX idx_token_grants_token_zone (api_token_id, zone_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_keys (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            role VARCHAR(8) NOT NULL,
            algorithm INT NOT NULL,
            key_tag INT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            state VARCHAR(16) NOT NULL,
            state_changed_at DATETIME NOT NULL,
            eligible_at DATETIME NOT NULL,
            max_signed_ttl INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_dnssec_keys_zone (zone_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            name VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_type INT NOT NULL,
            covered_record_type INT,
            ttl INT NOT NULL,
            rdata BLOB NOT NULL,
            expires_at DATETIME,
            record_set_digest VARCHAR(64),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_dnssec_records_zone (zone_id),
            INDEX idx_dnssec_records_expires (expires_at, zone_id)
        );
        "#,
    ]
}

/// Return the statement that seeds the built-in `default` DNSSEC policy.
pub(crate) fn default_policy_seed() -> &'static str {
    r#"
    INSERT INTO dnssec_policies (name, algorithm, denial, split_keys, signature_validity_days,
        signature_refresh_days, zsk_lifetime_days, created_at)
    SELECT 'default', 13, 'nsec3', FALSE, 14, 5, 0, ? FROM DUAL
    WHERE NOT EXISTS (SELECT 1 FROM dnssec_policies WHERE name = 'default');
    "#
}
