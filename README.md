# Aruba Mock

A self-hosted, Aruba-Central-shaped dashboard for your homelab. Single Docker
container. Adds devices, polls them over **SNMP**, runs read-only **SSH**
commands against them, and exposes:

- **AI Insights** — rule-based engine over real telemetry (CPU, memory, RF
  saturation, co-channel contention, offline detection).
- **AirMatch** — heuristic 2.4/5/6 GHz channel + tx-power planner that mirrors
  the *shape* of Aruba ARM/AirMatch (busiest-AP-first, neighbor-aware,
  DFS-aware on 5 GHz).

**It is not Aruba Central.** It does not push config to your devices. It only
reads via SNMP and runs allowlisted `show` / `display` / `get` SSH commands.

## Quick start (any docker host)

```bash
git clone <this folder>
cd aruba-mock
docker compose up -d --build
# open http://localhost:8080  (default creds admin / ChangeMe!)
```

The first start initializes a SQLite DB at `./data/aruba.db`.

## Unraid

Two paths.

### A. Docker Compose Manager (easiest)

1. Install the **Docker Compose Manager** plugin from Community Apps.
2. Copy this folder into `/mnt/user/appdata/aruba-mock/` on the Unraid box.
3. Edit `docker-compose.yml` — change the bind-mount to a stable path:

   ```yaml
   volumes:
     - /mnt/user/appdata/aruba-mock/data:/data
   ```

4. From Compose Manager: *Add Stack* → point at this folder → Compose Up.
5. Open `http://<unraid-ip>:8080`.

### B. Manual Unraid Docker template

If you'd rather build the image once and run it from the Unraid Docker tab:

```bash
docker build -t aruba-mock:latest /mnt/user/appdata/aruba-mock/
```

Then in Unraid → Docker → *Add Container*:

| Field          | Value                                          |
|----------------|------------------------------------------------|
| Repository     | `aruba-mock:latest`                            |
| Network type   | `bridge`                                       |
| Port           | `8080:8080`                                    |
| Path           | `/data` → `/mnt/user/appdata/aruba-mock/data`  |
| Variable       | `ARUBA_ADMIN_USER`     = `admin`               |
| Variable       | `ARUBA_ADMIN_PASSWORD` = *(your choice)*       |
| Variable       | `ARUBA_SECRET_KEY`     = *(random string)*     |
| Variable       | `ARUBA_POLL_INTERVAL`  = `60`                  |

## Adding a device

1. Sign in.
2. **Devices → + Add device.**
3. Provide the IP, SNMP version (v2c with `public` works for most lab gear),
   and optionally SSH credentials.

The poller picks the device up within ~5 seconds and populates `sysDescr`,
`sysUpTime`, `ifNumber`, and (if the device exposes the Aruba MIBs) CPU /
memory / client count. If the device is non-Aruba, you'll just see the
generic MIB-II values — that's fine.

## What gets polled

- **MIB-II:** `sysDescr`, `sysObjectID`, `sysUpTime`, `sysName`, `ifNumber`
- **Aruba enterprise (14823):** `wlsxSysExtCpuUsedPercent`,
  `wlsxSysExtMemoryUsedPercent`, `wlsxTotalNumOfUsers`, partial walk of the
  AP radio table.
- **Host Resources fallback:** `hrProcessorLoad` average when Aruba CPU is
  silent.

Polling runs every `ARUBA_POLL_INTERVAL` seconds (default 60). After every
cycle the insights engine recomputes.

## SSH

The SSH runner uses Netmiko. Set `ssh_device_type` per device — common
values: `aruba_os`, `aruba_osswitch`, `hp_procurve`, `cisco_ios`, `linux`.
Only commands starting with `show`, `display`, or `get` are accepted, and
substrings like `no `, `delete`, `reload`, etc. are blocked at the
allowlist.

## AirMatch

`/airmatch` runs the heuristic planner per band. It does not auto-apply.
The plan persists in the `airmatch_runs` table — you can re-open old runs
via the API at `/api/airmatch/run` (POST a band).

## Demo data

To play with AirMatch and Insights immediately, seed seven example APs:

```bash
docker exec -it aruba-mock python -m app.scripts.seed_demo
```

This adds APs in two sites (`lab` and `house`) with radios already populated
on 2.4 / 5 GHz, including some deliberately co-channel and busy ones so the
planner has work to do.

## API

OpenAPI docs at `/docs`. Highlights:

- `GET  /api/devices`
- `POST /api/devices`
- `POST /api/devices/{id}/poll`
- `POST /api/devices/{id}/ssh` `{ "command": "show version" }`
- `POST /api/airmatch/run`     `{ "band": "5", "allow_dfs": false }`
- `POST /api/insights/recompute`

All endpoints require the same admin session cookie as the UI.

## Environment variables

| Var                      | Default                          | Notes                                    |
|--------------------------|----------------------------------|------------------------------------------|
| `ARUBA_ADMIN_USER`       | `admin`                          |                                          |
| `ARUBA_ADMIN_PASSWORD`   | `ChangeMe!`                      | **Change me before exposing.**           |
| `ARUBA_SECRET_KEY`       | `change-me-to-a-random-string`   | Used for cookie signing.                 |
| `ARUBA_DB_PATH`          | `/data/aruba.db`                 | Persistent SQLite location.              |
| `ARUBA_POLL_INTERVAL`    | `60`                             | Seconds between SNMP polls.              |
| `ARUBA_POLL_TIMEOUT`     | `5`                              | Per-device SNMP/SSH timeout.             |
| `ARUBA_LOG_LEVEL`        | `info`                           | `debug` / `info` / `warning` / `error`.  |
| `ARUBA_ENABLE_POLLER`    | `true`                           | Set `false` to disable background poll.  |

## Troubleshooting

- **All devices stuck "unknown" or "offline":** SNMP isn't responding. From
  inside the container: `docker exec -it aruba-mock snmpwalk -v2c -c public
  <ip> system` — if that fails, the device or community is the issue.
- **SSH says "auth failed":** confirm `ssh_device_type` matches the gear,
  some Aruba switches need `aruba_osswitch`, controllers need `aruba_os`.
- **AirMatch returns "No APs on this band":** you need devices typed as
  `ap` *and* radios populated. Radio data needs to be inserted manually for
  now (real Aruba MIB walks are device-specific) — see
  `app/services/airmatch.py` for the data shape, or seed via the SQL API.

## Layout

```
app/
  main.py            # FastAPI app + lifespan
  config.py          # env-driven settings
  db.py / db_init.py # SQLAlchemy + sqlite
  models.py          # ORM models
  schemas.py         # Pydantic
  auth.py            # admin session cookie
  routes/
    pages.py         # HTML (HTMX) views
    api_devices.py   # REST CRUD
    api_actions.py   # poll / ssh / airmatch / recompute
  services/
    snmp.py          # pysnmp polling
    ssh.py           # netmiko allowlisted runner
    poller.py        # APScheduler poll loop
    insights.py      # rule engine
    airmatch.py      # channel/power planner
  templates/         # Jinja + Tailwind CDN + HTMX
```
