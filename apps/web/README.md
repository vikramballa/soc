# SentinelX web UI

React 19 + TypeScript + Vite + Tailwind CSS 4. Built once and served by the SentinelX API process
(`apps/web/dist`), so production needs no separate web server.

```bash
npm ci
npm run dev      # http://localhost:5173 — proxies /api to the API on :8000
npm run build    # writes dist/, picked up automatically by `sentinelx serve`
npx tsc -b       # type check
```

| Folder | Contents |
|---|---|
| `src/pages/` | One file per screen (Dashboard, Incidents, IncidentDetail, …) |
| `src/components/` | Shared UI: `ui.tsx` (buttons, inputs, cards…), `security.tsx` (severity, risk), overlays, charts |
| `src/lib/` | API client, auth context, formatting helpers, shared types |
| `public/` | Favicon and the pre-paint theme script (kept external for the strict CSP) |

Permissions in the UI only hide what a role cannot do; the API enforces every permission itself.
