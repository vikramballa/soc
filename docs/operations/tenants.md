# Organizations, users and roles

| Role | Can |
|---|---|
| Super admin | everything, every organization; platform actions (rule repository, custom rules, organizations, demo, platform audit) |
| Admin | users below admin, organization settings, ingest tokens, rule toggles, audit log (own organization) |
| Security analyst | investigate, resolve/close with a verdict, merge and create incidents, AI analyst, threat intel, response actions |
| IT operator | view; move incidents through open states (triage → contained), notes, assign, update assets, reports |
| Viewer | read-only (no reports, no admin) |

Full permission matrix: `apps/api/src/sentinelx/security/rbac.py` (tested in `tests/security/test_rbac.py`).

Rules enforced by the API (the UI mirrors them, but never relies on hiding):
- Only a super admin can create, edit or deactivate admins; an admin manages only lower roles (no peer lock-out,
  no minting of new admins). Nobody can change their own role or deactivate themselves.
- Recording a verdict, resolving and closing require `incident:close` (analyst and above).
- Incident owners must be active members of the organization.
- Role changes and deactivation take effect on the very next request; deactivation also ends all sessions.
- Denied attempts are written to the audit log (`authorization.denied`).

- Create organizations (MSSP): Administration → Organizations (super admin). Switch with the sidebar picker.
- Users: Administration → Users.
- CLI: `sentinelx create-user someone@example.com --role SECURITY_ANALYST --tenant acme`,
  `sentinelx reset-password someone@example.com`.

## Single sign-on (Keycloak)
1. `docker compose --profile sso up -d` (imports realm `sentinelx` with client `sentinelx-web`).
2. In Keycloak, copy the client secret to `KEYCLOAK_CLIENT_SECRET`; set `AUTH_MODE=both`,
   `KEYCLOAK_URL=http://localhost:8081`.
3. Give users a realm role `sentinelx:<ROLE>` and a user attribute `tenant` = organization slug
   (enable unmanaged attributes in the realm's user profile settings).
Users without a SentinelX role are refused. SSO is safe by construction: the IdP must assert
`email_verified`, an SSO identity is bound to its Keycloak subject, it can never take over an existing local
(password) account, and `sentinelx:SUPER_ADMIN` is capped to admin unless `OIDC_ALLOW_SUPER_ADMIN=true`.
