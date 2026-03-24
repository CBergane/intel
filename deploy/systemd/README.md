# systemd units — BorealSec Intel

## Units overview

| File | Type | Trigger |
|------|------|---------|
| `intel-web.service` | simple | always-on |
| `intel-ingest.service` | oneshot | every 15 min via timer |
| `intel-ingest.timer` | timer | boot +2 min, then 15 min |
| `intel-dark-ingest.service` | oneshot | every 30 min via timer |
| `intel-dark-ingest.timer` | timer | boot +5 min, then 30 min |
| `intel-prune.service` | oneshot | daily 03:00 via timer |
| `intel-prune.timer` | timer | daily 03:00 |

## Installation

```bash
# Copy all units
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo cp deploy/systemd/*.timer /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start web server
sudo systemctl enable --now intel-web.service

# Enable timers (activate services automatically)
sudo systemctl enable --now intel-ingest.timer
sudo systemctl enable --now intel-dark-ingest.timer
sudo systemctl enable --now intel-prune.timer

# Verify
sudo systemctl status intel-web.service
sudo systemctl list-timers intel-*

# Run ingest manually once to test
sudo systemctl start intel-ingest.service
sudo journalctl -u intel-ingest.service -f
```

## Assumptions

- **User:** `appuser`
- **App directory:** `/opt/intel/borealsec-intel`
- **Virtualenv:** `/opt/intel/venv`
- **Environment file:** `/opt/intel/.env` (contains all secrets — never committed to git)
- **Django settings:** `config.settings.prod`

## Debugging

```bash
# Follow web server logs live
journalctl -u intel-web.service -f

# Last hour of dark ingest (Tor, slow)
journalctl -u intel-dark-ingest.service --since "1 hour ago"

# Show all timers and next trigger times
systemctl list-timers --all

# Check if a specific unit failed
sudo systemctl status intel-ingest.service

# Re-run prune manually
sudo systemctl start intel-prune.service
sudo journalctl -u intel-prune.service -f
```

## Notes

- `intel-dark-ingest.service` has `TimeoutStartSec=120` because Tor circuits can be slow to establish.
- All timers use `Persistent=true` — a missed run (e.g. after reboot) will execute once on next start.
- No secrets appear in any unit file; everything is loaded from `EnvironmentFile=/opt/intel/.env`.
