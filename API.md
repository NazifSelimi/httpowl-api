# HTTPowl API (for the frontend)

Base: `https://httpowl.net/api`. JSON in/out. Auth = `owl_session` cookie (HttpOnly, set by signup/login), so use `credentials: "include"` (RTK Query: `fetchBaseQuery({ baseUrl: "/api", credentials: "include" })`).
Mutations must send `Content-Type: application/json`. Errors: `{"error": "plain words message"}` — show it as-is.

## Auth
| Method | Path | Body | Notes |
|---|---|---|---|
| POST | /auth/signup | `{email, password, name?}` | password 10–200 chars; logs in |
| POST | /auth/login | `{email, password}` | 401 wrong creds, 429 too many tries |
| POST | /auth/logout | – | 204 |
| GET | /auth/me | – | `{id, email, name}` or 401 |
| GET | /audit/me | `?before=<id>` | my own actions |

## Sites (role needed in brackets)
| Method | Path | Body / query |
|---|---|---|
| GET | /sites | → `[{id,name,domain,role,agent_last_seen_at}]` |
| POST | /sites | `{domain, name?}` → you are owner |
| GET | /sites/{id} [client] | adds `agent_online`, `agent_info`, `token_prefix` (admin+) |
| PATCH | /sites/{id} [admin] | `{domain, name}` |
| DELETE | /sites/{id} [owner] | |
| POST | /sites/{id}/agent-token [admin] | → `{token, install_command}` — shown once, old token stops working |

## Traffic
| Method | Path | Query |
|---|---|---|
| GET | /sites/{id}/stats [client] | `range=15m\|1h\|24h\|7d\|30d` or `from&to` (RFC3339). → `totals`, `series` (humans/bots/attacks/errors_5xx per bucket), `countries`; viewer+ also `top_ips`, `top_paths`, `top_reasons` |
| GET | /sites/{id}/requests [viewer] | `range`, `tag=human\|bot\|attack`, `ip`, `country=DE`, `status=404\|4xx\|5xx`, `path=/prefix`, `method`, `limit≤500`, `before=<next_before>` |
| WS | /sites/{id}/live [viewer] | `wss://httpowl.net/api/sites/{id}/live` → `{"type":"hello"}`, then `{"type":"requests","data":[{ts,ip,country,method,path,status,duration_ms,ua,tag,reason}]}` |

## Rules (blocks; every one is reversible)
| Method | Path | Body |
|---|---|---|
| GET | /sites/{id}/rules [viewer] | active first, then removed (last 30 days) |
| POST | /sites/{id}/rules/check [admin] | `{kind, value}` → `{ok, error?, explain}` — use for the confirm dialog |
| POST | /sites/{id}/rules [admin] | `{kind: ip\|cidr\|country\|bot, value, note?, expires_hours?}` → `{rule, explain, undo}`; 422 = refused (would block you/SSH/server/team) |
| DELETE | /sites/{id}/rules/{ruleId} [admin] | unblock → `{removed, undo}` |
| POST | /sites/{id}/rules/{ruleId}/restore [admin] | undo an unblock |

## Notes, team, audit
| Method | Path | Body |
|---|---|---|
| GET | /sites/{id}/notes [client] | last 30 daily notes `{day, body, stats}` |
| GET | /sites/{id}/notes/today [client] | live "so far today" |
| GET | /sites/{id}/team [viewer] | `{members, invites, roles}` |
| POST | /sites/{id}/team [admin] | `{email, role}` — admins may add viewer/client only; unknown email = invite |
| PATCH | /sites/{id}/team/{userId} [owner] | `{role}` |
| DELETE | /sites/{id}/team/{userId} [any: self = leave] | |
| DELETE | /sites/{id}/team/invites/{email} [admin] | |
| GET | /sites/{id}/audit [admin] | `?before=<id>` |

Roles: **owner** everything · **admin** blocks, token, invite viewers/clients · **viewer** read everything · **client** daily note + summary charts only.

## Agent endpoints (Bearer `owl_…` token)
`POST /ingest` (gzip JSON `{requests:[…]}`, ≤5000), `POST /agent/heartbeat`, `GET /agent/rules` (ETag).
