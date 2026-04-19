# Dashboard (React + Vite + Mapbox GL)

## Local dev

```powershell
cd frontend
npm install
npm run dev
```

## Mapbox token

Copy `.env.example` to `.env` and set `VITE_MAPBOX_TOKEN`. Restart `npm run dev` after changes.

Without a token, the UI still loads and shows setup instructions.

## Production build

```powershell
npm run build
```

Static output is written to `frontend/dist/` (host on S3+CloudFront, Amplify, or Vercel).
