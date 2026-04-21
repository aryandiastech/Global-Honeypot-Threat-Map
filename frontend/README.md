# Dashboard (React + Vite + Mapbox GL)

## Local dev

```powershell
cd frontend
npm install
npm run dev
```

## Environment variables

Copy `.env.example` to `.env`.

- **`VITE_MAPBOX_TOKEN`**: required for the Mapbox globe.
- **`VITE_API_URL`**: optional; set to the SAM output **HttpApiUrl** (no trailing slash) to load recent events from `GET /events`.

Restart `npm run dev` after changes.

## Production build

```powershell
npm run build
```

Static output is written to `frontend/dist/` (host on S3+CloudFront, Amplify, or Vercel).
