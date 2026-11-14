# GhostAP API (F061) and integrations (F055–F060)

The dashboard is a client of a JSON API. Everything it shows is available to scripts.
The full list of endpoints is generated from the code: `GET /api/openapi.json`
(OpenAPI 3; open it in any OpenAPI viewer).

## Signing in

| How the dashboard runs | What a script needs |
|---|---|
| `--host 127.0.0.1` (default) | nothing, but only requests addressed to `localhost`/`127.0.0.1` are answered |
| `--host 0.0.0.0` or another address | an API key, or the login token, as `Authorization: Bearer …` |

### API keys

```bash
python -m ghostap.apikeys create --name grafana --scope read
python -m ghostap.apikeys list
python -m ghostap.apikeys revoke 3
```

Or on the **System** page. A key is shown once; GhostAP stores only its SHA-256 hash.

- `read` keys can call `GET` endpoints only.
- `write` keys can also triage alerts and change settings.
- No key can create or revoke keys; that needs the dashboard itself.
- Actions done with a key appear in the audit log as `key:<name>`.

```bash
KEY=gk_...
curl -s -H "Authorization: Bearer $KEY" http://kali.local:8050/api/summary
curl -s -H "Authorization: Bearer $KEY" "http://kali.local:8050/api/alerts?detector=ghostap,deauth,flood"
curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
     -d '{"status": "investigating", "note": "checking with IT"}' \
     http://kali.local:8050/api/alerts/12/triage        # needs a write key
```

POST bodies must be JSON (`Content-Type: application/json`), also for actions without
parameters (send `{}`); anything else gets 415. Requests that a browser marks as coming from
another site (`Sec-Fetch-Site: cross-site`, or an `Origin` that is not this dashboard) get 403.
Scripts such as curl send neither header and are not affected.
Add `?session=<id>` to a GET to read a past session (ids from `GET /api/sessions`).

## Useful endpoints

| Endpoint | What it returns |
|---|---|
| `GET /api/summary` | counts, open alerts by level, the top alert, capture state (cheap; poll it) |
| `GET /api/alerts?detector=ghostap,deauth,flood` | every alert with its indicator breakdown and triage |
| `GET /api/ap?ssid=…&bssid=…` | one access point compared with its network |
| `GET /api/incidents` | alerts grouped into incidents with a timeline story |
| `GET /api/timeline?top=30&points=800` | risk lines (bounded for large sites) |
| `POST /api/alerts/<id>/triage` | `{"status": "new|investigating|confirmed|false_positive", "note": "…"}` |
| `GET /metrics` | Prometheus metrics |
| `GET /api/baselines/versions` | saved-baseline versions, pending changes and whether you may approve them |
| `GET /api/baselines/versions/<id>` | one version or proposal, with its content and a diff against the current baseline |
| `POST /api/baselines/versions/<id>/approve` · `/reject` · `/rollback` | admin only, body `{}` (reject: `{"reason": "…"}`) |

### Saved baselines: signing, versions and approval

Every change to the saved baseline (`data/monitored.json`) is a signed, numbered version
(`ghostap/baselines.py`). The signing key lives outside `data/`:
`~/.config/ghostap/baseline.key`, or the file named by `GHOSTAP_BASELINE_KEY_FILE`.
A file edited outside GhostAP is refused, by the API (HTTP 409) and at start-up, until someone
reviews it and runs `python -m ghostap.monitored trust --yes`.

The `POST /api/monitored/*` endpoints answer **200** with `"version"` when the change was applied,
and **202** with `"pending"` and `"message"` when it waits for approval:
- an analyst's change waits for an admin;
- with two or more admins, every change waits for a *second* admin;
- a baseline learned while the learning checks found possible signs of an attack (KARMA,
  look-alike names, tool fingerprints, two transmitters on one address, open and protected access
  points sharing a name, a freshly booted access point next to long-running ones) waits for an
  explicit approval, even from a lone admin.

`python -m ghostap.monitored history` lists the versions from the command line.

## Prometheus / Grafana (F060)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ghostap
    metrics_path: /metrics
    authorization: {credentials: gk_...}     # a read key (not needed on localhost)
    static_configs: [{targets: ["kali.local:8050"]}]
```

Metrics: `ghostap_open_alerts{level}`, `ghostap_alerts{detector}`, `ghostap_access_points`,
`ghostap_networks`, `ghostap_beacons`, `ghostap_beacons_last_minute`,
`ghostap_last_frame_age_seconds` (live; alert on this to catch a silent adapter),
`ghostap_score_round_seconds`, `ghostap_damaged_frames{reason}`, `ghostap_info`.
Turn the endpoint off with `api.metrics: false`.

## Notifications (F013, F055–F059)

Set `notifications.enabled: true` and configure channels in `config.yaml` (commented
examples there). Secrets stay in environment variables. Use **System → Send a test
message** to check them; every attempt is listed there and in the log file.

When messages are sent:

- **raised**: an alert reaches `min_level` for the first time;
- **escalated**: it goes from MEDIUM to HIGH;
- **reminder**: it is still active after `realert_minutes`.

Muted alerts and alerts marked false positive are never sent. Each channel sends at
most `max_per_minute`; held-back messages are counted in the next one. A failed delivery
is retried twice (after 1 s and 3 s) and then logged.

### Webhook payload (`format: json`)

```json
{"source": "ghostap", "version": "1.1.0", "event": "raised", "session": "20261113-…",
 "sent_at": 1763050000.1, "dashboard_url": "http://kali.local:8050",
 "alert": {"id": 12, "ssid": "MVSR_WiFi", "bssid": "00:c0:ca:de:ad:01", "level": "HIGH",
           "score": 77.4, "detector": "ghostap", "first_ts": …, "high_ts": …, "last_ts": …,
           "reasons": "security_downgrade (+19): …", "triage_status": "new"},
 "suppressed": 0}
```

The SSID came from the air: treat it as untrusted text in whatever receives it.

With `secret_env`, each request carries `X-GhostAP-Signature: sha256=<hex>`, an
HMAC-SHA256 of the raw body. Check it before trusting the message:

```python
import hashlib, hmac
def valid(body: bytes, header: str, secret: str) -> bool:
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header or "")
```

Other formats: `ntfy` (phone push through ntfy.sh, no account), `telegram` (bot),
`slack` (incoming webhook). E-mail uses SMTP with STARTTLS. Syslog sends RFC 5424 lines
over UDP or TCP with a JSON or ArcSight CEF body (facility local0; HIGH = critical,
MEDIUM = warning). `jsonl` appends one JSON object per message to a file.

### Desktop notifications (F055)

System → **Turn on desktop notifications** asks the browser for permission. The tab then
shows a system notification when a new alert appears while it is in the background.

## What was tested, and what was not

Every channel is tested against local fake receivers: an HTTP server, a UDP socket and a
fake SMTP class. Real ntfy, Telegram, Slack, SMTP servers and SIEMs were not contacted
from this project; those need your accounts or tokens.
