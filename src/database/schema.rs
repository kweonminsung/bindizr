pub fn get_table_creation_queries() -> Vec<&'static str> {
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            record_type VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            ttl INT,
            priority INT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            zone_id INT NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS zone_history (
            id INT PRIMARY KEY AUTO_INCREMENT,
            log TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            zone_id INT NOT NULL,
            FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
        );
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS record_history (
            id INT PRIMARY KEY AUTO_INCREMENT,
            log TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
