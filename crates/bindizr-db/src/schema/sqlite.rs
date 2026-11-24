//! SQLite DDL.

/// Return the statements that create the application schema.
pub(crate) fn table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            algorithm INTEGER NOT NULL,
            denial TEXT NOT NULL,
            key_layout TEXT NOT NULL DEFAULT 'csk',
            signature_validity_days INTEGER NOT NULL,
            signature_refresh_days INTEGER NOT NULL,
            zsk_lifetime_days INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            mname TEXT NOT NULL,
            rname TEXT NOT NULL,
            default_ttl INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            refresh INTEGER NOT NULL,
            retry INTEGER NOT NULL,
            expire INTEGER NOT NULL,
            minimum_ttl INTEGER NOT NULL,
            dnssec_policy_id INTEGER NULL,
            parent_ns_addrs TEXT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            description TEXT,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (dnssec_policy_id) REFERENCES dnssec_policies(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zones_dnssec_policy ON zones(dnssec_policy_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            display_value TEXT NOT NULL,
            ttl INTEGER NOT NULL,
            priority INTEGER,
            created_at DATETIME NOT NULL,
            zone_id INTEGER NOT NULL,
            CHECK ((record_type IN ('MX', 'SRV')) = (priority IS NOT NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_records_zone_name ON records(zone_id, name);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_records_zone_type ON records(zone_id, record_type);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_journal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            operation TEXT NOT NULL,
            record_name TEXT NOT NULL,
            record_type TEXT NOT NULL,
            record_value TEXT,
            record_rdata BLOB,
            record_ttl INTEGER NOT NULL,
            record_priority INTEGER,
            derived BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL,
            CHECK ((derived = TRUE AND record_value IS NULL AND record_rdata IS NOT NULL)
                OR (derived = FALSE AND record_value IS NOT NULL AND record_rdata IS NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_serial ON zone_journal(zone_id, serial);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_journal_created ON zone_journal(created_at);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            mname TEXT NOT NULL,
            rname TEXT NOT NULL,
            default_ttl INTEGER NOT NULL,
            refresh INTEGER NOT NULL,
            retry INTEGER NOT NULL,
            expire INTEGER NOT NULL,
            minimum_ttl INTEGER NOT NULL,
            source TEXT NOT NULL,
            actor_kind TEXT,
            actor_name TEXT,
            created_at DATETIME NOT NULL,
            CONSTRAINT chk_zone_versions_actor CHECK (
                (actor_kind IS NULL AND actor_name IS NULL)
                OR (actor_kind IS NOT NULL AND actor_name IS NOT NULL
                    AND actor_kind IN ('token', 'tsig_key'))
            ),
            UNIQUE(zone_id, serial),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_versions_created ON zone_versions(created_at);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at DATETIME NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            description TEXT,
            role_id INTEGER NOT NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME,
            last_used_at DATETIME,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_api_tokens_role ON api_tokens(role_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS catalog_zones (
            name TEXT PRIMARY KEY,
            digest TEXT NOT NULL,
            serial INTEGER NOT NULL
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_withdrawals (
            zone_id INTEGER PRIMARY KEY,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS tsig_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            algorithm TEXT NOT NULL,
            secret TEXT NOT NULL,
            role_id INTEGER NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_tsig_keys_role ON tsig_keys(role_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS secondaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            address TEXT UNIQUE NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            notify_tsig_key_id INTEGER NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (notify_tsig_key_id) REFERENCES tsig_keys(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_secondaries_notify_tsig_key ON secondaries(notify_tsig_key_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS transfer_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            zone_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            result TEXT NOT NULL,
            transport TEXT NOT NULL,
            incremental BOOLEAN NOT NULL,
            serial INTEGER NULL,
            created_at DATETIME NOT NULL,
            error_code TEXT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_transfer_log_client_zone ON transfer_log(client_ip, zone_id, id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_transfer_log_zone ON transfer_log(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_transfer_log_created ON transfer_log(created_at);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            target TEXT NOT NULL,
            response_code TEXT NOT NULL,
            result TEXT NOT NULL,
            actor_kind TEXT,
            actor_name TEXT,
            error_code TEXT NULL,
            requested_at DATETIME NOT NULL,
            CONSTRAINT chk_access_log_actor CHECK (
                (actor_kind IS NULL AND actor_name IS NULL)
                OR (actor_kind IS NOT NULL AND actor_name IS NOT NULL
                    AND actor_kind IN ('token', 'tsig_key'))
            )
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_access_log_requested ON access_log(requested_at);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_access_log_client ON access_log(client_ip);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_access_log_actor ON access_log(actor_name);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation TEXT NOT NULL,
            result TEXT NOT NULL,
            target_name TEXT,
            zone_name TEXT,
            record_id INTEGER,
            record_name TEXT,
            record_type TEXT,
            source TEXT NOT NULL,
            actor_kind TEXT,
            actor_name TEXT,
            created_at DATETIME NOT NULL,
            detail TEXT,
            CONSTRAINT chk_activity_log_actor CHECK (
                (actor_kind IS NULL AND actor_name IS NULL)
                OR (actor_kind IS NOT NULL AND actor_name IS NOT NULL
                    AND actor_kind IN ('token', 'tsig_key'))
            )
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_activity_log_created ON activity_log(created_at);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS role_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id INTEGER NOT NULL,
            zone_id INTEGER NULL,
            actions TEXT NOT NULL,
            record_name_pattern TEXT NOT NULL,
            record_types TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_role_grants_role_zone ON role_grants(role_id, zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_role_grants_zone ON role_grants(zone_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            algorithm INTEGER NOT NULL,
            key_tag INTEGER NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            state TEXT NOT NULL,
            state_changed_at DATETIME NOT NULL,
            eligible_at DATETIME NOT NULL,
            max_signed_ttl INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone ON dnssec_keys(zone_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            record_type INTEGER NOT NULL,
            covered_record_type INTEGER,
            ttl INTEGER NOT NULL,
            rdata BLOB NOT NULL,
            expires_at DATETIME,
            record_set_digest TEXT,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_dnssec_records_zone ON dnssec_records(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_dnssec_records_expires ON dnssec_records(expires_at, zone_id);
        "#,
    ]
}

/// Return the statement that seeds the built-in `default` DNSSEC policy.
pub(crate) fn default_policy_seed() -> &'static str {
    r#"
    INSERT INTO dnssec_policies (name, algorithm, denial, key_layout, signature_validity_days,
        signature_refresh_days, zsk_lifetime_days, created_at)
    SELECT 'default', 13, 'nsec3', 'csk', 14, 5, 0, ?
    WHERE NOT EXISTS (SELECT 1 FROM dnssec_policies WHERE name = 'default');
    "#
}

/// Ensure the built-in role exists. Binds its name, description and creation
/// time, then its name again for the existence check.
pub(crate) fn admin_role_seed() -> &'static str {
    r#"
    INSERT INTO roles (name, description, created_at)
    SELECT ?, ?, ?
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
