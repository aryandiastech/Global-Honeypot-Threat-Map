# Frontend Visualization

This page describes the user interface used to consume, observe, and engage with the threat intelligence data collected by the Global Honeypot Threat Map.

## Technologies Used
- **Framework**: React with Vite
- **Mapping Engine**: Mapbox GL JS (`mapbox-gl`)
- **Data Binding**: React Hooks (`useEffect`, `useState`) polling over HTTP

## The Live 3D Globe
Once the React application starts (via `npm run dev`), it connects to the Mapbox API to fetch geographic tile definitions. 
Because Mapbox supports 3D globe projections (`projection: "globe"`), we orient the map to view AWS Regions (Mumbai and N. Virginia) from a wide, global angle.

## Event Processing & Animation
Our deployment consists of an HTTP API Gateway connected to the `list_events_lambda`. The frontend simply polls `/events?limit=20` to grab the freshest logs:
1. It reads the source IP geographical coordinates (`geo_lat`, `geo_lon`).
2. It draws a `LineString` (an arc) in standard GeoJSON format from the attacker's physical location directly to the AWS node they hit.
3. It refreshes automatically every 15 seconds.

## Integrating AI: Unsupervised Botnet Colors
The crowning feature of the dashboard is its ML Integration. When events arrive, they include an integer `cluster_id` appended by our backend DBSCAN Lambda. 
- In the `src/App.tsx`, we intercept the `cluster_id` and map it to a predefined hex color array using mathematical modding.
- Random noise (isolated scanners) default to a low-opacity blue line (`cluster_id: -1`).
- Verified grouped Botnets (e.g., `BOTNET-1`, `BOTNET-2`) will glow brightly in distinct neon colors on the map.
- The Side Panel also displays this ID badge next to Cowrie's internal Session ID, allowing Threat Researchers to instantly group IPs by visual correlation!
