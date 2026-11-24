//! MySQL DDL: binary name comparison and 255-character index prefixes keep
//! utf8mb4 VARCHAR(1024) keys below InnoDB's 3,072-byte limit.
//! MEDIUMTEXT holds TXT values whose `\DDD` escapes can quadruple 65,535-byte RDATA.

/// Return the statements that create the application schema.
pub(crate) fn table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_policies (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) COLLATE utf8mb4_bin UNIQUE NOT NULL,
            algorithm INT NOT NULL,
            denial VARCHAR(8) NOT NULL,
            key_layout VARCHAR(5) NOT NULL DEFAULT 'csk',
            signature_validity_days INT NOT NULL,
            signature_refresh_days INT NOT NULL,
            zsk_lifetime_days INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(1020) CHARACTER SET ascii COLLATE ascii_bin UNIQUE NOT NULL,
            mname VARCHAR(1020) CHARACTER SET ascii NOT NULL,
            rname VARCHAR(1020) NOT NULL,
            default_ttl BIGINT NOT NULL,
            serial BIGINT NOT NULL,
            refresh INT NOT NULL,
            retry INT NOT NULL,
            expire INT NOT NULL,
            minimum_ttl BIGINT NOT NULL,
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
            ttl BIGINT NOT NULL,
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
            serial BIGINT NOT NULL,
            operation VARCHAR(10) NOT NULL,
            record_name VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            record_value MEDIUMTEXT,
            record_rdata BLOB,
            record_ttl BIGINT NOT NULL,
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
            serial BIGINT NOT NULL,
            mname TEXT NOT NULL,
            rname TEXT NOT NULL,
            default_ttl BIGINT NOT NULL,
            refresh INT NOT NULL,
            retry INT NOT NULL,
            expire INT NOT NULL,
            minimum_ttl BIGINT NOT NULL,
            source VARCHAR(16) NOT NULL,
            actor_kind VARCHAR(16),
            actor_name VARCHAR(255),
            created_at DATETIME NOT NULL,
            CONSTRAINT chk_zone_versions_actor CHECK (
                (actor_kind IS NULL AND actor_name IS NULL)
                OR (actor_kind IS NOT NULL AND actor_name IS NOT NULL
                    AND actor_kind IN ('token', 'tsig_key'))
            ),
            UNIQUE KEY uq_zone_serial (zone_id, serial),
            INDEX idx_zone_versions_created (created_at),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) COLLATE utf8mb4_bin UNIQUE NOT NULL,
            description VARCHAR(255),
            created_at DATETIME NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            description VARCHAR(255),
            role_id INT NOT NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME,
            last_used_at DATETIME,
            FOREIGN KEY (role_id) REFERENCES roles(id),
            INDEX idx_api_tokens_role (role_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS catalog_zones (
            name VARCHAR(1020) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
            digest VARCHAR(64) NOT NULL,
            serial BIGINT NOT NULL
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
            role_id INT NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id),
            INDEX idx_tsig_keys_role (role_id)
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
            INDEX idx_secondaries_notify_tsig_key (notify_tsig_key_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS transfer_log (
            id INT PRIMARY KEY AUTO_INCREMENT,
            client_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,
            zone_id INT NOT NULL,
            kind VARCHAR(4) NOT NULL,
            result VARCHAR(7) NOT NULL,
            transport VARCHAR(3) NOT NULL,
            incremental BOOLEAN NOT NULL,
            serial BIGINT NULL,
            created_at DATETIME NOT NULL,
            error_code TEXT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_transfer_log_client_zone (client_ip, zone_id, id),
            INDEX idx_transfer_log_zone (zone_id),
            INDEX idx_transfer_log_created (created_at)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS access_log (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            source VARCHAR(8) NOT NULL,
            client_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,
            method VARCHAR(16) NOT NULL,
            target TEXT COLLATE utf8mb4_bin NOT NULL,
            response_code VARCHAR(16) NOT NULL,
            result VARCHAR(6) NOT NULL,
            actor_kind VARCHAR(16),
            actor_name VARCHAR(255) COLLATE utf8mb4_bin,
            error_code TEXT NULL,
            requested_at DATETIME NOT NULL,
            CONSTRAINT chk_access_log_actor CHECK (
                (actor_kind IS NULL AND actor_name IS NULL)
                OR (actor_kind IS NOT NULL AND actor_name IS NOT NULL
                    AND actor_kind IN ('token', 'tsig_key'))
            ),
            INDEX idx_access_log_requested (requested_at),
            INDEX idx_access_log_client (client_ip),
            INDEX idx_access_log_actor (actor_name)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS activity_log (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            operation VARCHAR(64) NOT NULL,
            result VARCHAR(64) NOT NULL,
            target_name VARCHAR(1024) COLLATE utf8mb4_bin,
            zone_name VARCHAR(1024) COLLATE utf8mb4_bin,
            record_id INT,
            record_name VARCHAR(1024) COLLATE utf8mb4_bin,
            record_type VARCHAR(16),
            source VARCHAR(16) NOT NULL,
            actor_kind VARCHAR(16),
            actor_name VARCHAR(255),
            created_at DATETIME(6) NOT NULL,
            detail TEXT,
            CONSTRAINT chk_activity_log_actor CHECK (
                (actor_kind IS NULL AND actor_name IS NULL)
                OR (actor_kind IS NOT NULL AND actor_name IS NOT NULL
                    AND actor_kind IN ('token', 'tsig_key'))
            ),
            INDEX idx_activity_log_created (created_at)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS role_grants (
            id INT PRIMARY KEY AUTO_INCREMENT,
            role_id INT NOT NULL,
            zone_id INT NULL,
            actions VARCHAR(512) NOT NULL,
            record_name_pattern VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_role_grants_role_zone (role_id, zone_id),
            INDEX idx_role_grants_zone (zone_id)
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
            max_signed_ttl BIGINT NOT NULL DEFAULT 0,
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
            ttl BIGINT NOT NULL,
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
    INSERT INTO dnssec_policies (name, algorithm, denial, key_layout, signature_validity_days,
        signature_refresh_days, zsk_lifetime_days, created_at)
    SELECT 'default', 13, 'nsec3', 'csk', 14, 5, 0, ? FROM DUAL
    WHERE NOT EXISTS (SELECT 1 FROM dnssec_policies WHERE name = 'default');
    "#
}

/// Ensure the built-in role exists. Binds its name, description and creation
/// time, then its name again for the existence check.
pub(crate) fn admin_role_seed() -> &'static str {
    r#"
    INSERT INTO roles (name, description, created_at)
    SELECT ?, ?, ? FROM DUAL
    WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = ?);
    "#
}

/// Give the built-in role its one grant, every action in all zones, unless it
/// holds one. Binds the action list, the creation time and the role's name.
pub(crate) fn admin_grant_seed() -> &'static str {
    r#"
    INSERT INTO role_grants (role_id, zone_id, actions, record_name_pattern, record_types, created_at)
    SELECT r.id, NULL, ?, '*', '*', ? FROM roles r
    WHERE r.name = ?
      AND NOT EXISTS (SELECT 1 FROM role_grants g WHERE g.role_id = r.id);
    "#
}
