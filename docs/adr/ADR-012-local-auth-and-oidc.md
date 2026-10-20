# ADR-012: Local accounts by default, Keycloak OIDC optional (BFF pattern)

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Keycloak is the natural choice for enterprise SSO, but requiring it would make single-machine installs heavy.

## Decision
Built-in local accounts (Argon2id, server-side sessions, lockout) work out of the box. With `AUTH_MODE=oidc|both`, the API performs the authorization-code + PKCE flow itself and issues the same HttpOnly session — tokens never reach the browser; API clients may use Keycloak bearer tokens validated against JWKS. Roles map from realm roles `sentinelx:<ROLE>`, tenant from a `tenant` claim.

## Consequences
Works without extra services; SSO when needed; one session model in the UI.
