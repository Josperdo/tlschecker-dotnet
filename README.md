# TLS & Cert Health CLI (C#/.NET 8)

Small CLI that checks sites for:
- `http://` → **redirects to https**,
- **HTTPS reachability** + status,
- **HSTS** header presence,
- **TLS protocol** negotiated,
- **Certificate issuer**, **expiry**, and **days remaining**.

## Quickstart
```powershell
dotnet build
dotnet run --project src/TlsCheck -- --in targets.txt --out examples/sample.jsonl --fail-if-expiring 30 