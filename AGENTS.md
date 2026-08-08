# AGENTS.md — goSureAuth (Go client SDK)

## Purpose
Official Go client for the sureAuth hosted auth service. One-line
integration: `New()` reads `SUREAUTH_SERVER_URL` + `SUREAUTH_API_KEY`, then
`client.Auth(ctx, identifier, credential)` — the library handles API-key
auth, project scoping, OTP challenges (SendOTP/VerifyOTP/CompletePhone) and
the hosted popup flow (LoginURL/CompleteLogin). Credentials never hardcoded.

## Ownership
- Client SDK tier of the sureAuth family. Consumes the engine's `/api/v1/*`
  + `/oauth/*` API (contract in `../sureauth/API.md`).
- Stdlib-only (zero deps) — keep it that way.

## Local Contracts
- Zero-config via env; explicit config via `NewWithConfig`.
- `Auth`/`Login` return tokens OR `Challenges` — never treat a challenge as
  an error.
- Token refresh is explicit (`TokenManager` + `RefreshToken`); sessions are
  the app's responsibility (no persistence in the lib).
- API errors map to typed `*APIError{Code, Message, Status}`.
- No stdout noise.

## Work Guidance
- Keep the engine contract mirrored exactly (field names snake_case JSON).
- Any new engine endpoint ships here as a typed method + README example.

## Verification
- `go build ./...`, `go vet ./...`, `go test ./...` (httptest fixtures).
- README examples must compile (they are the docs).

## Child DOX Index
Flat library — none.
