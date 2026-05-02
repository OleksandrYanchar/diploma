# Postman Collection

This directory contains the API collection and per-endpoint reference files for the Zero Trust Financial Platform API.

## Importing the collection

1. Open Postman
2. Click **Import** -> **File**
3. Select `api-v1/diploma-api-v1.postman_collection.json`
4. The collection **Zero Trust Financial Platform API** will appear in your workspace

## Environment variables

After importing, configure these collection variables (Postman -> collection -> Variables tab):

| Variable | Description | Example value |
|----------|-------------|---------------|
| `baseUrl` | Backend base URL | `http://127.0.0.1:8000` |
| `access_token` | Access JWT from login response | (paste from login) |
| `access_token_verified` | Access JWT for a verified user | (paste from login with verified account) |
| `access_token_unverified` | Access JWT for an unverified user | (paste from register without verifying) |
| `access_token_admin` | Access JWT for an admin user | (paste after role promotion) |
| `refresh_token` | Refresh JWT from login response | (paste from login) |
| `step_up_token` | Step-up token from POST /auth/step-up | (paste from step-up response) |

The backend test stack runs on `http://127.0.0.1:8000`. Start it with:
```bash
make start-test-env && make migrate-test
```

## Per-endpoint reference files

Each `endpoint-*.json` file describes one endpoint: its HTTP method, path, authentication requirement, request shape, and expected response scenarios. These files are specification artefacts — they are not imported into Postman directly.

| File | Endpoint |
|------|----------|
| `endpoint-post-auth-register.json` | `POST /auth/register` |
| `endpoint-post-auth-login.json` | `POST /auth/login` |
| `endpoint-get-auth-verify-email.json` | `GET /auth/verify-email` |
| `endpoint-post-auth-refresh.json` | `POST /auth/refresh` |
| `endpoint-post-auth-logout.json` | `POST /auth/logout` |
| `endpoint-post-auth-mfa-setup.json` | `POST /auth/mfa/setup` |
| `endpoint-post-auth-mfa-enable.json` | `POST /auth/mfa/enable` |
| `endpoint-post-auth-mfa-disable.json` | `POST /auth/mfa/disable` |
| `endpoint-post-auth-password-change.json` | `POST /auth/password/change` |
| `endpoint-post-auth-password-reset-request.json` | `POST /auth/password/reset/request` |
| `endpoint-post-auth-password-reset-confirm.json` | `POST /auth/password/reset/confirm` |
| `endpoint-post-auth-step-up.json` | `POST /auth/step-up` |
| `endpoint-get-users-me.json` | `GET /users/me` |
| `endpoint-get-admin-ping.json` | `GET /admin/ping` |
| `endpoint-get-accounts-me.json` | `GET /accounts/me` |
| `endpoint-post-transactions-transfer.json` | `POST /transactions/transfer` |
| `endpoint-get-transactions-history.json` | `GET /transactions/history` |
| `endpoint-get-health.json` | `GET /health` |
