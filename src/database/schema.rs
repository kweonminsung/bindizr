pub fn get_mysql_table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            primary_ns VARCHAR(255) NOT NULL,
            primary_ns_ip VARCHAR(255) NOT NULL,
            admin_email VARCHAR(255) NOT NULL,
            ttl INT NOT NULL,
            serial INT NOT NULL,
            refresh INT NOT NULL DEFAULT 86400,
            retry INT NOT NULL DEFAULT 7200,
            expire INT NOT NULL DEFAULT 3600000,
            minimum_ttl INT NOT NULL DEFAULT 86400,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            ttl INT,
            priority INT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INT NOT NULL,
            UNIQUE (name, record_type),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_history (
            id INT PRIMARY KEY AUTO_INCREMENT,
            log TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INT NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS record_history (
            id INT PRIMARY KEY AUTO_INCREMENT,
            log TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            record_id INT NOT NULL,
            FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INT PRIMARY KEY AUTO_INCREMENT,
            token VARCHAR(64) UNIQUE NOT NULL,
            description VARCHAR(255),
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME
        );
        "#,
    ]
}

pub fn get_postgres_table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            primary_ns VARCHAR(255) NOT NULL,
            primary_ns_ip VARCHAR(255) NOT NULL,
            admin_email VARCHAR(255) NOT NULL,
            ttl INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            refresh INTEGER NOT NULL DEFAULT 86400,
            retry INTEGER NOT NULL DEFAULT 7200,
            expire INTEGER NOT NULL DEFAULT 3600000,
            minimum_ttl INTEGER NOT NULL DEFAULT 86400,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            ttl INTEGER,
            priority INTEGER,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INTEGER NOT NULL,
            UNIQUE (name, record_type),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_history (
            id SERIAL PRIMARY KEY,
            log TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INTEGER NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS record_history (
            id SERIAL PRIMARY KEY,
            log TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            record_id INTEGER NOT NULL,
            FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id SERIAL PRIMARY KEY,
            token VARCHAR(64) UNIQUE NOT NULL,
            description VARCHAR(255),
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            last_used_at TIMESTAMP
        );
        "#,
    ]
}

pub fn get_sqlite_table_creation_queries() -> Vec<&'static str> {
    vec![
        r#"
        CREATE TABLE IF NOT EXISTS zones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            primary_ns TEXT NOT NULL,
            primary_ns_ip TEXT NOT NULL,
            admin_email TEXT NOT NULL,
            ttl INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            refresh INTEGER NOT NULL DEFAULT 86400,
            retry INTEGER NOT NULL DEFAULT 7200,
            expire INTEGER NOT NULL DEFAULT 3600000,
            minimum_ttl INTEGER NOT NULL DEFAULT 86400,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INTEGER,
            priority INTEGER,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INTEGER NOT NULL,
            UNIQUE (name, record_type),
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            zone_id INTEGER NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS record_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            record_id INTEGER NOT NULL,
            FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME
        );
        "#,
    ]
}
