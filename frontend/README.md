# Dashboard (React + Vite + Mapbox GL)

## Local dev

```powershell
cd frontend
npm install
npm run dev
```

## Environment variables

Copy `.env.example` to `.env`.

- **`VITE_MAPBOX_TOKEN`**: required for the Mapbox globe (free token, see `../DEMO.md`). Everything else works without it.
- **`VITE_API_URL`**: `http://localhost:8000` for the local demo backend (`python demo/server.py --live`), the SAM output **HttpApiUrl** for AWS, or empty to use the bundled offline snapshot (`public/demo-snapshot.json`).
- **`VITE_POLL_MS`** / **`VITE_EVENTS_LIMIT`**: refresh interval and events per poll (AWS read API caps at 100).

Regenerate the offline snapshot with `python demo/server.py --export-snapshot frontend/public/demo-snapshot.json`.

## Code map

| File | Role |
|------|------|
| `src/useThreatFeed.ts` | polling `GET /events` (+ `/stats` when available), snapshot fallback |
| `src/ThreatMap.tsx` | Mapbox globe: great-circle arcs, attacker dots + popups, pulsing sensors |
| `src/analytics.ts` | client-side stats, cluster colours, tactic tags |
| `src/App.tsx` | layout: KPIs, botnet list (click to filter), top origins/credentials, live feed |

Restart `npm run dev` after changes.

## Production build

```powershell
npm run build
```

Static output is written to `frontend/dist/` (host on S3+CloudFront, Amplify, or Vercel).
