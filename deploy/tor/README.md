# Intel Tor Proxy Container

Rootless Podman container running Tor as a SOCKS5 proxy for dark intel ingestion.
Listens on `127.0.0.1:9050`. Only accepts connections from `127.0.0.1` and the
Podman network range `10.89.0.0/16`.

## Build and install

```bash
# Build the Tor image
cd deploy/tor
podman build -t localhost/intel-tor:latest .

# Copy systemd unit
sudo cp deploy/tor/intel-tor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now intel-tor.service

# Wait ~30s for Tor to bootstrap, then verify
sudo systemctl status intel-tor.service
podman logs intel-tor
```

## Verify Tor connectivity

```bash
# Should return: {"IsTor":true,...}
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

## Security properties

| Property | Value |
|----------|-------|
| `--cap-drop ALL` | No Linux capabilities |
| `--security-opt no-new-privileges` | Cannot escalate privileges |
| `--read-only` | Immutable root filesystem |
| `--tmpfs /tmp` | Writable tmpfs for temp files only |
| `--publish 127.0.0.1:9050:9050` | Loopback only, not 0.0.0.0 |
| `SocksPolicy` | Accepts only 127.0.0.1 and 10.89.0.0/16 |
| `ExitPolicy reject *:*` | Never acts as exit node |
| `ClientOnly 1` | Client only, not a relay |

## Debugging

```bash
# Follow Tor bootstrap logs
podman logs -f intel-tor

# Check systemd unit status
sudo systemctl status intel-tor.service
journalctl -u intel-tor.service -f

# Rebuild after torrc changes
podman build -t localhost/intel-tor:latest deploy/tor/
sudo systemctl restart intel-tor.service
```

## Environment variables (in /opt/intel/.env)

```
TOR_SOCKS_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_ENABLED=true
```

Set `TOR_ENABLED=false` to disable Tor routing without removing the container
(useful for debugging with clearnet sources).
