# Bindizr

Synchronizing bind9(DNS) records with DB

### Concepts

<img src="https://github.com/user-attachments/assets/c53df52e-b658-404d-b9ea-b4a0756c0d49" width="420px" height="200x">

### Dependencies

- [hyper](https://hyper.rs/)
- [sqlx](https://github.com/launchbadge/sqlx)
- MySQL or SQLite

```bash
sea-orm-cli generate entity -u sqlite://bindizr.db -o src/database/model
```
