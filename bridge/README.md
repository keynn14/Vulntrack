# VulnTrack Greenbone GMP Bridge

Thin Python bridge using `python-gvm` over the Greenbone `gvmd` Unix socket so VulnTrack (.NET) can start authorized scans, poll task progress, and fetch XML reports (`a994b278-1f62-11e1-96ac-406186ea4fc5`).

## Required Environment Variables

| Variable | Description |
| --- | --- |
| `GVMD_SOCKET` | Path to mounted `gvmd.sock` (e.g. `/run/gvmd/gvmd.sock`) |
| `GMP_USER` | Greenbone GMP service username |
| `GMP_PASSWORD` | Greenbone GMP service password |
| `BRIDGE_API_KEY` | Shared secret checked against `X-Api-Key` header |
| `PORT_LIST_ID` | UUID of the authorized port list |
| `SCAN_CONFIG_ID` | UUID of the scan config (e.g. *Full and fast*) |
| `SCANNER_ID` | UUID of the OpenVAS Default scanner |

## Looking Up IDs with `gvm-cli`

```bash
# Port lists (e.g. All IANA assigned TCP)
gvm-cli --gmp-username "$GMP_USER" --gmp-password "$GMP_PASSWORD" \
  socket --socketpath /run/gvmd/gvmd.sock \
  --xml "<get_port_lists/>"

# Scan configs (e.g. Full and fast)
gvm-cli --gmp-username "$GMP_USER" --gmp-password "$GMP_PASSWORD" \
  socket --socketpath /run/gvmd/gvmd.sock \
  --xml "<get_configs/>"

# Scanners (e.g. OpenVAS Default)
gvm-cli --gmp-username "$GMP_USER" --gmp-password "$GMP_PASSWORD" \
  socket --socketpath /run/gvmd/gvmd.sock \
  --xml "<get_scanners/>"
```
