Bindizr - DNS Synchronization Service for BIND9

Bindizr is a Rust-based daemon that synchronizes DNS zone records between BIND9 and a MySQL database. 
It provides an HTTP API for managing DNS zones and automatically applies changes to BIND9 via RNDC.

Main Features:
- Synchronize BIND9 DNS zone files with MySQL, PostgreSQL, or SQLite database.
  - Expose HTTP API for external management.
  - Automatically reload BIND9 zones after updates.
  - Token-based API authentication.

Configuration:
  - The default configuration file is located at:
      /etc/bindizr/bindizr.conf
  - Configuration is written in INI format. It includes sections for API, MySQL, BIND9, and logging.

Quick Start:
  1. Install and configure BIND9 and RNDC.
  2. Create the bindizr configuration file.
  3. Start the bindizr service:

     bindizr start

  4. Generate API tokens for authentication:

     bindizr token create

Documentation:
  Full documentation and examples are available on the project GitHub repository:

    https://github.com/kweonminsung/bindizr

License:
  Bindizr is licensed under the Apache License 2.0.

Maintainer:
  kweonminsung kevin136583@gmail.com
