# Dashboard (React + Vite + MapLibre / Mapbox GL)

## Local dev

```powershell
cd frontend
npm install
npm run dev
```

## Environment variables

Copy `.env.example` to `.env`.

- **`VITE_MAPBOX_TOKEN`**: optional. Empty = MapLibre + OpenFreeMap globe (no key); a `pk.` token switches to Mapbox. Only the library in use is downloaded (dynamic import).
- **`VITE_API_URL`**: `http://localhost:8000` for the local demo backend (`python demo/server.py`), the SAM output **HttpApiUrl** for AWS, or empty to use the bundled offline snapshot (`public/demo-snapshot.json`).
- **`VITE_POLL_MS`** / **`VITE_EVENTS_LIMIT`**: refresh interval and events per poll (AWS read API caps at 100).

Regenerate the offline snapshot with `python demo/server.py --export-snapshot frontend/public/demo-snapshot.json`.

## Code map

| File | Role |
|------|------|
| `src/useThreatFeed.ts` | polling `GET /events` (+ `/stats` when available), snapshot fallback |
| `src/ThreatMap.tsx` | globe (MapLibre or Mapbox): great-circle arcs, attacker dots + popups, pulsing sensors |
| `src/analytics.ts` | client-side stats, cluster colours, tactic tags |
| `src/App.tsx` | layout: KPIs, Deploy / take-offline button (starts/stops the live attack feed), new-attack pop-ups, attack database (sessions), botnet list (click to filter), top origins/credentials |
| `src/AttackDetails.tsx` | attacker panel: origin, threat intel, ML classification, session timelines, raw stored record |

Restart `npm run dev` after changes.

## Production build

```powershell
npm run build
```

Static output is written to `frontend/dist/` (host on S3+CloudFront, Amplify, or Vercel).
