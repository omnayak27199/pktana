/** Device box size — must match canvas.js */
const DEV_W = 80;
const DEV_H = 72;

/** Cable attach point on the device edge that faces the peer (falls back to bottom port). */
export function connectionPoint(dev, peer) {
  const peerCx = peer.x + DEV_W / 2;
  const peerCy = peer.y + DEV_H / 2;
  const cx = dev.x + DEV_W / 2;
  const cy = dev.y + DEV_H / 2;
  const dx = peerCx - cx;
  const dy = peerCy - cy;

  if (Math.abs(dx) < 4 && Math.abs(dy) < 4) {
    return { x: cx, y: dev.y + DEV_H };
  }

  const hw = DEV_W / 2;
  const hh = DEV_H / 2;

  // Exit through the edge that most directly faces the peer.
  if (Math.abs(dx) / hw >= Math.abs(dy) / hh) {
    return { x: dx > 0 ? dev.x + DEV_W : dev.x, y: cy };
  }
  return { x: cx, y: dy > 0 ? dev.y + DEV_H : dev.y };
}

/** @deprecated use connectionPoint */
export function portPosition(dev) {
  return { x: dev.x + DEV_W / 2, y: dev.y + DEV_H };
}

/**
 * Orthogonal cable path between two devices — same geometry for wires and packet animation.
 * @param {import('./models.js').Device} fromDev
 * @param {import('./models.js').Device} toDev
 * @returns {{ x: number, y: number }[]}
 */
export function linkRoutePoints(fromDev, toDev) {
  const start = connectionPoint(fromDev, toDev);
  const end = connectionPoint(toDev, fromDev);
  const path = buildOrthogonalPath(start, end);
  return orientPath(path, start, end);
}

/** Build a symmetric orthogonal polyline between two anchor points. */
function buildOrthogonalPath(start, end) {
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  const adx = Math.abs(dx);
  const ady = Math.abs(dy);

  if (adx < 4 && ady < 4) return [start, end];

  const stub = 14;

  // Same row — drop a short bus below both devices.
  if (ady <= 18) {
    const busY = Math.max(start.y, end.y) + stub;
    if (adx < 4) return [start, end];
    return [
      start,
      { x: start.x, y: busY },
      { x: end.x, y: busY },
      end,
    ];
  }

  // Same column — straight vertical run.
  if (adx <= 18) {
    return [start, end];
  }

  const midX = (start.x + end.x) / 2;
  const midY = (start.y + end.y) / 2;

  // Prefer vertical-first when height difference dominates (e.g. switch → PC above).
  if (ady >= adx) {
    return [
      start,
      { x: start.x, y: midY },
      { x: end.x, y: midY },
      end,
    ];
  }

  // Primarily horizontal separation.
  return [
    start,
    { x: midX, y: start.y },
    { x: midX, y: end.y },
    end,
  ];
}

/** Ensure polyline runs from `start` to `end` (animation direction). */
function orientPath(points, start, end) {
  if (points.length < 2) return points;
  const first = points[0];
  const last = points[points.length - 1];
  const forward = dist(first, start) + dist(last, end);
  const reverse = dist(last, start) + dist(first, end);
  if (reverse < forward) return points.slice().reverse();
  return points;
}

function dist(a, b) {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

/** @param {{ x: number, y: number }[]} points */
export function pointsToPathD(points) {
  if (!points.length) return '';
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
}

/** @param {{ x: number, y: number }[]} points */
function polylineMetrics(points) {
  /** @type {{ a: {x:number,y:number}, b: {x:number,y:number}, len: number, start: number }[]} */
  const segments = [];
  let total = 0;
  for (let i = 0; i < points.length - 1; i++) {
    const a = points[i];
    const b = points[i + 1];
    const len = Math.hypot(b.x - a.x, b.y - a.y);
    segments.push({ a, b, len, start: total });
    total += len;
  }
  return { segments, total };
}

/** @param {{ x: number, y: number }[]} points @param {number} t 0..1 */
export function pointOnPolyline(points, t) {
  if (!points.length) return { x: 0, y: 0 };
  if (points.length === 1 || t <= 0) return { ...points[0] };
  if (t >= 1) return { ...points[points.length - 1] };

  const { segments, total } = polylineMetrics(points);
  if (total === 0) return { ...points[0] };

  let d = t * total;
  for (const seg of segments) {
    if (d <= seg.len || seg === segments[segments.length - 1]) {
      const r = seg.len > 0 ? Math.min(1, d / seg.len) : 0;
      return {
        x: seg.a.x + (seg.b.x - seg.a.x) * r,
        y: seg.a.y + (seg.b.y - seg.a.y) * r,
      };
    }
    d -= seg.len;
  }
  return { ...points[points.length - 1] };
}

/** @param {import('./models.js').Topology} topo @param {string} fromId @param {string} toId */
export function findDirectLink(topo, fromId, toId) {
  return (
    topo.links.find(
      (l) =>
        (l.aDeviceId === fromId && l.bDeviceId === toId) ||
        (l.aDeviceId === toId && l.bDeviceId === fromId),
    ) ?? null
  );
}

/** Undirected path for drawing a link (stable regardless of link record order). */
export function linkDrawPoints(aDev, bDev) {
  const start = connectionPoint(aDev, bDev);
  const end = connectionPoint(bDev, aDev);
  return buildOrthogonalPath(start, end);
}
