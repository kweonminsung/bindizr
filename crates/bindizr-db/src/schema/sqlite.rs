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
            split_keys BOOLEAN NOT NULL DEFAULT FALSE,
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
            refresh INTEGER NOT NULL DEFAULT 300,
            retry INTEGER NOT NULL DEFAULT 60,
            expire INTEGER NOT NULL DEFAULT 3600000,
            minimum_ttl INTEGER NOT NULL DEFAULT 86400,
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
            change_source TEXT NOT NULL,
            changed_by TEXT,
            created_at DATETIME NOT NULL,
            UNIQUE(zone_id, serial),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_versions_created ON zone_versions(created_at);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            description TEXT,
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL,
            expires_at DATETIME,
            last_used_at DATETIME
        );
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
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL
        );
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
        CREATE INDEX IF NOT EXISTS idx_secondaries_notify_key ON secondaries(notify_tsig_key_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS tsig_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            tsig_key_id INTEGER NOT NULL,
            record_name_pattern TEXT NOT NULL,
            record_types TEXT NOT NULL,
            can_write BOOLEAN NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_tsig_grants_zone ON tsig_grants(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_tsig_grants_key ON tsig_grants(tsig_key_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS token_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            api_token_id INTEGER NOT NULL,
            record_name_pattern TEXT NOT NULL,
            record_types TEXT NOT NULL,
            can_write BOOLEAN NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (api_token_id) REFERENCES api_tokens(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_token_grants_zone ON token_grants(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_token_grants_token_zone ON token_grants(api_token_id, zone_id);
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
            rrset_digest TEXT,
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
    INSERT INTO dnssec_policies (name, algorithm, denial, split_keys, signature_validity_days,
        signature_refresh_days, zsk_lifetime_days, created_at)
    SELECT 'default', 13, 'nsec3', FALSE, 14, 5, 0, ?
    WHERE NOT EXISTS (SELECT 1 FROM dnssec_policies WHERE name = 'default');
    "#
}
