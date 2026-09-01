//! Table-creation DDL for each backend, run at startup to bring the schema up.
//!
//! Name columns are `VARCHAR(512)`, not 255: rows hold the escaped presentation
//! form, whose `\` escapes can nearly double the 253-byte wire limit.

pub(crate) fn mysql_table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            mname VARCHAR(255) NOT NULL,
            rname VARCHAR(255) NOT NULL,
            default_ttl INT NOT NULL,
            serial INT NOT NULL,
            refresh INT NOT NULL DEFAULT 300,
            retry INT NOT NULL DEFAULT 60,
            expire INT NOT NULL DEFAULT 3600000,
            minimum_ttl INT NOT NULL DEFAULT 86400,
            dnssec_denial VARCHAR(8) NOT NULL DEFAULT 'nsec',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(512) NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            display_value TEXT NOT NULL,
            ttl INT NOT NULL,
            priority INT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INT NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_records_zone_name (zone_id, name),
            INDEX idx_records_zone_type (zone_id, record_type)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_journal (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            serial INT NOT NULL,
            operation VARCHAR(10) NOT NULL,
            record_name VARCHAR(512) NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            record_value TEXT,
            record_rdata BLOB,
            record_ttl INT NOT NULL,
            record_priority INT,
            derived BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK ((derived = TRUE AND record_value IS NULL AND record_rdata IS NOT NULL)
                OR (derived = FALSE AND record_value IS NOT NULL AND record_rdata IS NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_zone_serial (zone_id, serial)
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_zone_serial (zone_id, serial),
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS catalog_zone_state (
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
            name VARCHAR(255) UNIQUE NOT NULL,
            algorithm VARCHAR(32) NOT NULL,
            secret VARCHAR(255) NOT NULL,
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_tsig_policies (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            tsig_key_id INT NOT NULL,
            record_name_pattern VARCHAR(512) NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys(id),
            INDEX idx_zone_tsig_policies_zone (zone_id),
            INDEX idx_zone_tsig_policies_key (tsig_key_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_token_policies (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            api_token_id INT NOT NULL,
            record_name_pattern VARCHAR(512) NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (api_token_id) REFERENCES api_tokens(id) ON DELETE CASCADE,
            INDEX idx_zone_token_policies_zone (zone_id),
            INDEX idx_zone_token_policies_token_zone (api_token_id, zone_id)
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
            state_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            eligible_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            max_signed_ttl INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_dnssec_keys_zone (zone_id)
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            zone_id INT NOT NULL,
            name VARCHAR(512) NOT NULL,
            record_type INT NOT NULL,
            covered_record_type INT,
            ttl INT NOT NULL,
            rdata BLOB NOT NULL,
            expires_at DATETIME,
            rrset_digest VARCHAR(64),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            INDEX idx_dnssec_records_zone (zone_id),
            INDEX idx_dnssec_records_expires (expires_at)
        );
        "#,
    ]
}

pub(crate) fn postgres_table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            mname VARCHAR(255) NOT NULL,
            rname VARCHAR(255) NOT NULL,
            default_ttl INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            refresh INTEGER NOT NULL DEFAULT 300,
            retry INTEGER NOT NULL DEFAULT 60,
            expire INTEGER NOT NULL DEFAULT 3600000,
            minimum_ttl INTEGER NOT NULL DEFAULT 86400,
            dnssec_denial VARCHAR(8) NOT NULL DEFAULT 'nsec',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id SERIAL PRIMARY KEY,
            name VARCHAR(512) NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            display_value TEXT NOT NULL,
            ttl INTEGER NOT NULL,
            priority INTEGER,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INTEGER NOT NULL,
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
            id SERIAL PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            operation VARCHAR(10) NOT NULL,
            record_name VARCHAR(512) NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            record_value TEXT,
            record_rdata BYTEA,
            record_ttl INTEGER NOT NULL,
            record_priority INTEGER,
            derived BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK ((derived = TRUE AND record_value IS NULL AND record_rdata IS NOT NULL)
                OR (derived = FALSE AND record_value IS NOT NULL AND record_rdata IS NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_serial ON zone_journal(zone_id, serial);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_versions (
            id SERIAL PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            mname TEXT NOT NULL,
            rname TEXT NOT NULL,
            default_ttl INTEGER NOT NULL,
            refresh INTEGER NOT NULL,
            retry INTEGER NOT NULL,
            expire INTEGER NOT NULL,
            minimum_ttl INTEGER NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(zone_id, serial),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            token VARCHAR(64) UNIQUE NOT NULL,
            description VARCHAR(255),
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS catalog_zone_state (
            name VARCHAR(255) PRIMARY KEY,
            digest VARCHAR(64) NOT NULL,
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
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            algorithm VARCHAR(32) NOT NULL,
            secret VARCHAR(255) NOT NULL,
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_tsig_policies (
            id SERIAL PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            tsig_key_id INTEGER NOT NULL,
            record_name_pattern VARCHAR(512) NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_tsig_policies_zone ON zone_tsig_policies(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_tsig_policies_key ON zone_tsig_policies(tsig_key_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_token_policies (
            id SERIAL PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            api_token_id INTEGER NOT NULL,
            record_name_pattern VARCHAR(512) NOT NULL,
            record_types VARCHAR(255) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (api_token_id) REFERENCES api_tokens(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_token_policies_zone ON zone_token_policies(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_token_policies_token_zone ON zone_token_policies(api_token_id, zone_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_keys (
            id SERIAL PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            role VARCHAR(8) NOT NULL,
            algorithm INTEGER NOT NULL,
            key_tag INTEGER NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            state VARCHAR(16) NOT NULL,
            state_changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            eligible_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            max_signed_ttl INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone ON dnssec_keys(zone_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS dnssec_records (
            id SERIAL PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            name VARCHAR(512) NOT NULL,
            record_type INTEGER NOT NULL,
            covered_record_type INTEGER,
            ttl INTEGER NOT NULL,
            rdata BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            rrset_digest VARCHAR(64),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_dnssec_records_zone ON dnssec_records(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_dnssec_records_expires ON dnssec_records(expires_at);
        "#,
    ]
}

pub(crate) fn sqlite_table_creation_queries() -> Vec<&'static str> {
    vec![
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
            dnssec_denial TEXT NOT NULL DEFAULT 'nsec',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INTEGER NOT NULL,
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK ((derived = TRUE AND record_value IS NULL AND record_rdata IS NOT NULL)
                OR (derived = FALSE AND record_value IS NOT NULL AND record_rdata IS NULL)),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_serial ON zone_journal(zone_id, serial);
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(zone_id, serial),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            description TEXT,
            is_global BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS catalog_zone_state (
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_tsig_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            tsig_key_id INTEGER NOT NULL,
            record_name_pattern TEXT NOT NULL,
            record_types TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys(id)
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_tsig_policies_zone ON zone_tsig_policies(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_tsig_policies_key ON zone_tsig_policies(tsig_key_id);
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_token_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            api_token_id INTEGER NOT NULL,
            record_name_pattern TEXT NOT NULL,
            record_types TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
            FOREIGN KEY (api_token_id) REFERENCES api_tokens(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_token_policies_zone ON zone_token_policies(zone_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_zone_token_policies_token_zone ON zone_token_policies(api_token_id, zone_id);
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
            state_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            eligible_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            max_signed_ttl INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
        CREATE INDEX IF NOT EXISTS idx_dnssec_records_expires ON dnssec_records(expires_at);
        "#,
    ]
}
