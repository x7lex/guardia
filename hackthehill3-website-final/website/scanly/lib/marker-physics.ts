export interface Body {
  x: number; y: number; vx: number; vy: number; dragging: boolean
}
export interface Size { width: number; height: number; radius?: number }
export interface Bounds { left: number; top: number; right: number; bottom: number }

export type Zone = "safe" | "review" | "unsafe"
export function zoneCenter(zone: Zone, width: number, top: number, height: number) {
  const available = Math.max(1, height - top)
  return { x: width * (zone === "safe" ? 1 / 6 : zone === "unsafe" ? 5 / 6 : 0.5),
    y: top + available * 0.5 }
}
export function zoneScale(x: number, y: number, center: { x: number; y: number }, width: number, height: number) {
  const distance = Math.hypot((x - center.x) / Math.max(1, width / 6), (y - center.y) / Math.max(1, height * 0.4))
  return 1 - 0.18 * Math.min(1, distance)
}

export function keepInside(body: Body, size: Size, bounds: Bounds) {
  const hx = size.width / 2, hy = size.height / 2
  const minX = bounds.left + hx, maxX = bounds.right - hx
  const minY = bounds.top + hy, maxY = bounds.bottom - hy
  const x = minX > maxX ? (bounds.left + bounds.right) / 2 : Math.max(minX, Math.min(maxX, body.x))
  const y = minY > maxY ? (bounds.top + bounds.bottom) / 2 : Math.max(minY, Math.min(maxY, body.y))
  if ((x > body.x && body.vx < 0) || (x < body.x && body.vx > 0)) body.vx *= -0.65
  if ((y > body.y && body.vy < 0) || (y < body.y && body.vy > 0)) body.vy *= -0.65
  body.x = x; body.y = y
}

export function separate(a: Body, b: Body, sa: Size, sb: Size) {
  const dx = b.x - a.x, dy = b.y - a.y
  // Minkowski sum of two rounded rectangles: straight edges meet exactly,
  // while corner contacts follow the visible corner arcs.
  const radius = Math.min(sa.radius ?? 0, sa.width / 2, sa.height / 2) + Math.min(sb.radius ?? 0, sb.width / 2, sb.height / 2)
  const qx = Math.abs(dx) - ((sa.width + sb.width) / 2 - radius)
  const qy = Math.abs(dy) - ((sa.height + sb.height) / 2 - radius)
  const outside = Math.hypot(Math.max(0, qx), Math.max(0, qy))
  const distance = radius - outside - Math.min(Math.max(qx, qy), 0)
  if (distance <= 0) return
  const wa = a.dragging ? 0 : 1, wb = b.dragging ? 0 : 1
  if (!wa && !wb) return
  let nx = 0, ny = 0
  if (outside > 0) {
    nx = Math.max(0, qx) / outside * (dx >= 0 ? 1 : -1)
    ny = Math.max(0, qy) / outside * (dy >= 0 ? 1 : -1)
  } else if (qx > qy) nx = dx >= 0 ? 1 : -1
  else ny = dy >= 0 ? 1 : -1
  a.x -= nx * distance * wa / (wa + wb); a.y -= ny * distance * wa / (wa + wb)
  b.x += nx * distance * wb / (wa + wb); b.y += ny * distance * wb / (wa + wb)
  const speed = (b.vx - a.vx) * nx + (b.vy - a.vy) * ny
  if (speed < 0) {
    const impulse = -1.65 * speed / (wa + wb)
    a.vx -= impulse * nx * wa; a.vy -= impulse * ny * wa
    b.vx += impulse * nx * wb; b.vy += impulse * ny * wb
  }
}
