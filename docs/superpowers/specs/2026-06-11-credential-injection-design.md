# Credential injection (managed mode) — design

Date: 2026-06-11
Status: approved

## Problem

Today pgproxy is a pure pass-through for Postgres authentication: every
client must hold real upstream (Neon) credentials. We want internal
apps to connect with nothing but `pgproxy.internal:<port>/<dbname>` —
no username, no password — with credentials held only in the proxy's
`DESTINATION_PG_DBS` Fly secret.

## Decisions (settled with Amit)

- **Only `dbname` is client-overridable.** The client's startup `user`
  is ignored in managed mode. Rationale: Postgres clients always send
  a username (drivers auto-fill the OS user when the connection string
  omits it), and a client password can only be obtained by challenging,
  which kills clients that have no password configured. So client-side
  user/password override is unimplementable without breaking the
  primary "dbname-only connection string" use case.
- **No per-entry `params` map** (statement_timeout etc.). Guardrails
  are managed on Neon via `ALTER ROLE` when needed.
- **CancelRequest relay deferred.** Query cancellation (psql Ctrl+C,
  driver context cancellation) does not work through the proxy. It was
  already broken for all connections in this fork (the initial-magic
  check rejects cancel packets), so nothing regresses. Documented.
- **Passthrough mode preserved.** Entries without credentials behave
  exactly as today — the escape hatch for admin/personal credentials.

## Config schema

`DESTINATION_PG_DBS` entries gain three optional fields:

```json
{"name":"rw", "listen":5432, "target":"ep-xxx.aws.neon.tech:5432",
 "dbname":"main", "user":"app_user", "password":"s3cret"}
```

- `user` and `password` both set → managed mode.
- Both empty → passthrough mode (today's behavior).
- One without the other → fatal config error at startup.
- `dbname` optional; only meaningful in managed mode (default database
  when the client doesn't pick one). `dbname` without `user` is a
  config error too, to avoid silently-ignored config.

## Managed connection flow

Unchanged: peer classification (Fly 6PN / Tailscale / reject), identity
lookup (WhoIs / PTR+TXT), client-side TLS-or-plaintext handling with
the self-signed cert, application_name attribution rules.

New, replacing the byte-level startup forward + splice:

1. Read and parse the client `StartupMessage` (protocol v3 only;
   anything else, e.g. CancelRequest, is rejected with a clear log).
2. Pick the effective database: the client's `database` param, except
   when it is absent or equal to the client's `user` param — drivers
   that weren't given a database auto-fill it with the username, so
   `database == user` is treated as "not specified" → config `dbname`
   applies (possibly empty → upstream defaults it to the user name).
3. Pick `application_name`: client's value if set, else the injected
   peer identity (existing rules).
4. All other startup params (client_encoding, options, …) forward as
   session runtime params. `user`, `database`, `application_name` are
   handled above and excluded from the generic forward.
5. The proxy connects upstream itself via `jackc/pgx/v5/pgconn`
   (handles SCRAM-SHA-256/md5/cleartext) using the configured
   user/password and the same strict TLS as today: configured CA pool,
   ServerName = upstream host, MinVersion TLS 1.2. pgconn config is
   built via `ParseConfig` then field overrides; `Fallbacks` cleared so
   env vars can't leak in.
6. On success the proxy hijacks the authenticated connection and sends
   the client: `AuthenticationOk`, each upstream `ParameterStatus`,
   `BackendKeyData` (upstream's real PID/secret), `ReadyForQuery` with
   the upstream transaction status. Then both directions revert to the
   existing dumb `io.Copy` splice.
7. On upstream failure the client receives a proper Postgres
   `ErrorResponse` (severity FATAL) instead of a hang, and the error is
   counted in the per-DB expvar metrics.

## Plaintext startup detection fix

The current initial-packet check matches plaintext startups against an
exact 8-byte constant, which only matches startup messages whose total
length is exactly 86 bytes — i.e. `sslmode=disable` clients are
arbitrarily rejected today depending on param lengths. Since 6PN apps
will commonly use `sslmode=disable`, the check is fixed (both modes) to
accept any v3 startup: bytes 4..8 == 0x00030000 and a sane length.
CancelRequest magic remains rejected.

## Surface changes

- Dev page: per-DB shows mode (managed/passthrough), copy-paste
  connection string (`postgres://pgproxy.internal:5432/dbname`),
  default user and dbname names. Passwords are never rendered.
- readme.md: new section on managed credentials, the dbname-only
  override rule, the cancel limitation, updated JSON examples.
- New dependency: `github.com/jackc/pgx/v5` (pgconn + pgproto3).

## Testing

- Unit: config validation (cred pairing, dbname-without-user),
  database-choice heuristic, startup param parsing, plaintext startup
  detection, client-side handshake message synthesis (decoded with
  pgproto3).
- End-to-end: fake in-process Postgres server (TLS with a generated CA,
  cleartext password auth) behind a real proxy listener; a pgconn
  client connects with no credentials and asserts the upstream saw the
  configured user/password/database and the session splices queries.
  SCRAM specifically is delegated to pgconn (battle-tested; Neon uses
  it).
- All existing tests keep passing.
