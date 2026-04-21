# Frontend Visualization (React + Mapbox)

## Dashboard features (current)

- Optional Mapbox globe (dark style, fog, navigation controls)
- “Recent events” panel fetching `GET /events`
- Auto-refresh polling (15s) when `VITE_API_URL` is configured

Repo location: `frontend/`

## Environment variables

Create `frontend/.env` from `.env.example`:

- `VITE_API_URL`: SAM output `HttpApiUrl` (no trailing slash)
- `VITE_MAPBOX_TOKEN`: Mapbox public token (only needed for the globe)

## Why Mapbox + Globe projection

- supports globe projection and rich styling
- later: draw arcs with GeoJSON lines and animate them by timestamp

## Next visualization steps

- Add geo-IP enrichment so each `src_ip` has `(lat, lon)`.
- Map AWS region nodes to fixed lat/lon points.
- Draw **great-circle arcs** (or approximated segments) from origin → AWS node.

