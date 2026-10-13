import { useEffect, useRef, useState } from "react";
import type { GeoJSONSource, LngLatLike, Map as GLMap, MapLayerMouseEvent, PopupOptions } from "maplibre-gl";
import { clusterColor, clusterTactic, countryCode, isBotnet } from "./analytics";
import type { ClusterSummary, RemoteEvent } from "./types";

/** Honeypot sensor locations (AWS regions in config/deployment-regions.json). */
export const REGION_NODES: Record<string, { lon: number; lat: number; label: string }> = {
  "ap-south-1": { lon: 72.8777, lat: 19.076, label: "Mumbai sensor (ap-south-1)" },
  "us-east-1": { lon: -77.0369, lat: 38.9072, label: "N. Virginia sensor (us-east-1)" },
};
const DEFAULT_REGION = "ap-south-1";
const FRESH_MS = 90_000;
const MAX_ARCS = 400;

/** Free, key-less dark basemap (https://openfreemap.org) used when no Mapbox token is set. */
const FREE_STYLE_URL = "https://tiles.openfreemap.org/styles/dark";
const VIEW = { center: [45, 25] as [number, number], zoom: 1.45, pitch: 30, bearing: -10 };

export type MapEngine = "mapbox" | "maplibre";

type PopupCtor = new (opts: PopupOptions) => {
  setLngLat(at: LngLatLike): { setHTML(html: string): { addTo(map: GLMap): unknown } };
};

/**
 * Create the globe with whichever engine is available. Only the chosen library is
 * downloaded (dynamic import). Mapbox and MapLibre share the API used here, so the
 * rest of the component treats both as a MapLibre `Map`.
 */
async function createGlobe(container: HTMLElement, token: string | undefined): Promise<{ map: GLMap; Popup: PopupCtor }> {
  if (token) {
    const [{ default: mapboxgl }] = await Promise.all([import("mapbox-gl"), import("mapbox-gl/dist/mapbox-gl.css")]);
    mapboxgl.accessToken = token;
    const map = new mapboxgl.Map({ container, style: "mapbox://styles/mapbox/dark-v11", projection: "globe", ...VIEW });
    map.addControl(new mapboxgl.NavigationControl({ visualizePitch: true }), "top-right");
    map.on("style.load", () =>
      map.setFog({ color: "rgb(10,14,24)", "high-color": "rgb(30,50,90)", "horizon-blend": 0.08, "space-color": "rgb(4,6,12)", "star-intensity": 0.35 }),
    );
    return { map: map as unknown as GLMap, Popup: mapboxgl.Popup as unknown as PopupCtor };
  }

  const [maplibre, worker] = await Promise.all([
    import("maplibre-gl"),
    // MapLibre locates its worker next to its own file, which Vite relocates — hand it a bundled worker instead.
    import("maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url"),
    import("maplibre-gl/dist/maplibre-gl.css"),
  ]);
  maplibre.setWorkerUrl(worker.default);
  // MapLibre's globe renders smaller than Mapbox's at the same zoom.
  const map = new maplibre.Map({ container, style: FREE_STYLE_URL, attributionControl: { compact: true }, ...VIEW, zoom: 2.1 });
  map.addControl(new maplibre.NavigationControl({ visualizePitch: true }), "top-right");
  map.on("style.load", () => {
    map.setProjection({ type: "globe" });
    map.setSky({
      "sky-color": "#04060c",
      "horizon-color": "#1e325a",
      "fog-color": "#0a0e18",
      "atmosphere-blend": ["interpolate", ["linear"], ["zoom"], 0, 1, 5, 1, 7, 0],
    });
  });
  return { map, Popup: maplibre.Popup as unknown as PopupCtor };
}

type LonLat = [number, number];

/** Great-circle interpolation so arcs follow the globe instead of cutting through it. */
function greatCircle([lon1, lat1]: LonLat, [lon2, lat2]: LonLat, steps = 48): LonLat[] {
  const rad = Math.PI / 180;
  const p1 = [Math.cos(lat1 * rad) * Math.cos(lon1 * rad), Math.cos(lat1 * rad) * Math.sin(lon1 * rad), Math.sin(lat1 * rad)];
  const p2 = [Math.cos(lat2 * rad) * Math.cos(lon2 * rad), Math.cos(lat2 * rad) * Math.sin(lon2 * rad), Math.sin(lat2 * rad)];
  const dot = Math.min(1, Math.max(-1, p1[0] * p2[0] + p1[1] * p2[1] + p1[2] * p2[2]));
  const omega = Math.acos(dot);
  if (omega < 1e-6) return [[lon1, lat1], [lon2, lat2]];
  const out: LonLat[] = [];
  let prevLon = lon1;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const a = Math.sin((1 - t) * omega) / Math.sin(omega);
    const b = Math.sin(t * omega) / Math.sin(omega);
    const x = a * p1[0] + b * p2[0];
    const y = a * p1[1] + b * p2[1];
    const z = a * p1[2] + b * p2[2];
    let lon = Math.atan2(y, x) / rad;
    // keep longitudes continuous across the antimeridian
    while (lon - prevLon > 180) lon -= 360;
    while (lon - prevLon < -180) lon += 360;
    prevLon = lon;
    out.push([lon, Math.atan2(z, Math.sqrt(x * x + y * y)) / rad]);
  }
  return out;
}

/** Popup HTML is built from enrichment data (third-party geo/org strings) — escape it. */
const esc = (v: unknown) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const safeColor = (v: unknown) => (/^#[0-9a-f]{6}$/i.test(String(v)) ? String(v) : "#8b9bb8");

const regionOf = (e: RemoteEvent) => (e.aws_region && REGION_NODES[e.aws_region] ? e.aws_region : DEFAULT_REGION);

type Props = {
  /** Mapbox token; when empty the free MapLibre + OpenFreeMap globe is used. */
  token?: string;
  events: RemoteEvent[];
  clusters: ClusterSummary[];
  focusCluster: number | null;
  onArcCount: (n: number) => void;
};

export default function ThreatMap({ token, events, clusters, focusCluster, onArcCount }: Props) {
  const mapEl = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<GLMap | null>(null);
  const [ready, setReady] = useState(false);
  const [mapError, setMapError] = useState<string | null>(null);

  // --- create the map once per token
  useEffect(() => {
    const container = mapEl.current;
    if (!container) return;
    setMapError(null);

    let disposed = false;
    let map: GLMap | null = null;
    let raf = 0;

    createGlobe(container, token)
      .then(({ map: created, Popup }) => {
        if (disposed) {
          created.remove();
          return;
        }
        map = created;
        const m = created;
        m.on("error", (e: { error?: { message?: string } }) => setMapError(e.error?.message ?? "Map error"));

        // Add our layers as soon as the style is parsed — "load" would also wait for every basemap tile.
        const init = () => {
          const empty = { type: "FeatureCollection" as const, features: [] };
          m.addSource("arcs", { type: "geojson", data: empty });
          m.addSource("attackers", { type: "geojson", data: empty });
          m.addSource("sensors", {
            type: "geojson",
            data: {
              type: "FeatureCollection",
              features: Object.entries(REGION_NODES).map(([id, n]) => ({
                type: "Feature" as const,
                properties: { id, label: n.label },
                geometry: { type: "Point" as const, coordinates: [n.lon, n.lat] },
              })),
            },
          });

          m.addLayer({
            id: "arcs",
            type: "line",
            source: "arcs",
            layout: { "line-cap": "round" },
            paint: {
              "line-color": ["get", "color"],
              "line-width": ["case", ["get", "fresh"], 2.6, 1.1],
              "line-opacity": ["case", ["get", "dim"], 0.06, ["get", "fresh"], 0.95, 0.45],
            },
          });
          m.addLayer({
            id: "attackers",
            type: "circle",
            source: "attackers",
            paint: {
              "circle-color": ["get", "color"],
              "circle-radius": ["interpolate", ["linear"], ["get", "abuse"], 0, 3, 100, 7],
              "circle-opacity": ["case", ["get", "dim"], 0.12, 0.9],
              "circle-stroke-color": "#0b0f17",
              "circle-stroke-width": 1,
            },
          });
          m.addLayer({
            id: "sensor-halo",
            type: "circle",
            source: "sensors",
            paint: { "circle-color": "#38f2c4", "circle-radius": 14, "circle-opacity": 0.18, "circle-blur": 0.6 },
          });
          m.addLayer({
            id: "sensors",
            type: "circle",
            source: "sensors",
            paint: { "circle-color": "#38f2c4", "circle-radius": 6, "circle-stroke-color": "#eafff8", "circle-stroke-width": 2 },
          });

          const popup = (html: string, at: LngLatLike) =>
            new Popup({ closeButton: false, className: "threatPopup", maxWidth: "280px" }).setLngLat(at).setHTML(html).addTo(m);

          m.on("click", "attackers", (ev: MapLayerMouseEvent) => {
            const p = ev.features?.[0]?.properties as Record<string, string> | undefined;
            if (!p) return;
            popup(
              `<div class="pTitle"><span class="cc">${esc(p.flag)}</span> ${esc(p.ip)}</div>
               <div>${esc(p.place)}</div><div class="pMuted">${esc(p.org)}</div>
               <div>Abuse score: <b>${esc(p.abuse)}</b>/100 · ${esc(p.events)} events</div>
               <div style="color:${safeColor(p.color)}">${esc(p.botnet)}</div>`,
              ev.lngLat,
            );
          });
          m.on("click", "sensors", (ev: MapLayerMouseEvent) => {
            const p = ev.features?.[0]?.properties as Record<string, string> | undefined;
            if (p) popup(`<div class="pTitle">${esc(p.label)}</div><div class="pMuted">Cowrie SSH honeypot · port 2222</div>`, ev.lngLat);
          });
          for (const layer of ["attackers", "sensors"]) {
            m.on("mouseenter", layer, () => (m.getCanvas().style.cursor = "pointer"));
            m.on("mouseleave", layer, () => (m.getCanvas().style.cursor = ""));
          }

          setReady(true);
        };
        if (m.isStyleLoaded()) init();
        else m.once("style.load", init);

        // Pulse the sensor halos.
        const pulse = (t: number) => {
          if (m.getLayer("sensor-halo")) {
            const k = (Math.sin(t / 450) + 1) / 2;
            m.setPaintProperty("sensor-halo", "circle-radius", 10 + 10 * k);
            m.setPaintProperty("sensor-halo", "circle-opacity", 0.28 - 0.18 * k);
          }
          raf = requestAnimationFrame(pulse);
        };
        raf = requestAnimationFrame(pulse);

        mapRef.current = m;
      })
      .catch((err: unknown) => setMapError(err instanceof Error ? err.message : "Could not load the map library"));

    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      setReady(false);
      mapRef.current = null;
      map?.remove();
    };
  }, [token]);

  // --- (re)draw data whenever events change or the map becomes ready
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready) return;

    const tactic = new Map(clusters.map((c) => [c.cluster_id, clusterTactic(c)]));
    const geo = events.filter((e) => typeof e.geo_lat === "number" && typeof e.geo_lon === "number" && e.src_ip);
    const now = Date.now();

    // one arc per (attacker, sensor) pair — newest event wins
    const arcs = new Map<string, RemoteEvent>();
    const attackers = new Map<string, { e: RemoteEvent; n: number }>();
    for (const e of geo) {
      const key = `${e.src_ip}|${regionOf(e)}`;
      if (!arcs.has(key)) arcs.set(key, e);
      const a = attackers.get(e.src_ip!);
      if (a) a.n++;
      else attackers.set(e.src_ip!, { e, n: 1 });
    }

    const dimmed = (e: RemoteEvent) => focusCluster !== null && Number(e.cluster_id) !== focusCluster;

    const arcFeatures = [...arcs.values()].slice(0, MAX_ARCS).map((e) => {
      const node = REGION_NODES[regionOf(e)];
      const fresh = now - (Date.parse(e.received_at ?? "") || 0) < FRESH_MS;
      return {
        type: "Feature" as const,
        properties: { color: clusterColor(e.cluster_id), fresh, dim: dimmed(e) },
        geometry: {
          type: "LineString" as const,
          coordinates: greatCircle([Number(e.geo_lon), Number(e.geo_lat)], [node.lon, node.lat]),
        },
      };
    });

    const attackerFeatures = [...attackers.values()].map(({ e, n }) => ({
      type: "Feature" as const,
      properties: {
        ip: e.src_ip,
        color: clusterColor(e.cluster_id),
        abuse: Number(e.abuse_score ?? 0),
        dim: dimmed(e),
        events: n,
        flag: countryCode(e.geo_country),
        place: [e.geo_city, e.geo_country_name ?? e.geo_country].filter(Boolean).join(", "),
        org: e.geo_org ?? "",
        botnet: isBotnet(e.cluster_id)
          ? `BOTNET-${e.cluster_id} · ${tactic.get(Number(e.cluster_id)) ?? ""}`
          : "Lone scanner (noise)",
      },
      geometry: { type: "Point" as const, coordinates: [Number(e.geo_lon), Number(e.geo_lat)] },
    }));

    (map.getSource("arcs") as GeoJSONSource).setData({ type: "FeatureCollection", features: arcFeatures });
    (map.getSource("attackers") as GeoJSONSource).setData({ type: "FeatureCollection", features: attackerFeatures });
    onArcCount(arcFeatures.length);
  }, [events, clusters, focusCluster, ready, onArcCount]);

  return (
    <>
      {mapError ? <div className="banner">Map error: {mapError}</div> : null}
      <div ref={mapEl} className="map" />
    </>
  );
}
