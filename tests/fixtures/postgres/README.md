# Postgres E2E Fixture

This fixture is generic and contains no project-specific data.

```bash
pnpm provider:build:postgres
docker compose -f tests/fixtures/postgres/docker-compose.yml up -d --wait
AIVAULT_E2E_POSTGRES=1 cargo test --test e2e_postgres
```

The default connection URL used by the test is:

```text
postgresql://postgres:postgres@localhost:55432/aivault_postgres_test?sslmode=disable
```
