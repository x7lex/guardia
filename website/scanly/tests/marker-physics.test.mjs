import test from 'node:test'
import assert from 'node:assert/strict'
import { separate, keepInside, zoneCenter, zoneScale } from '../lib/marker-physics.ts'
const body = (x, y, dragging = false, vx = 0) => ({ x, y, vx, vy: 0, dragging })
const size = { width: 100, height: 80, radius: 12 }

test('flat edges collide without an invisible gap', () => {
  const a = body(100, 100), b = body(195, 100)
  separate(a, b, size, size)
  assert.equal(b.x - a.x, 100)
  const touching = body(a.x + 100, 100)
  separate(a, touching, size, size)
  assert.equal(touching.x - a.x, 100)
})
test('rounded corners do not collide while their visible arcs are apart', () => {
  const a = body(100, 100), b = body(198, 178)
  separate(a, b, size, size)
  assert.equal(a.x, 100)
  assert.equal(b.x, 198)
})
test('moving a held card transfers momentum before release', () => {
  const held = body(100, 100, true, 12), other = body(195, 100)
  separate(held, other, size, size)
  assert.equal(held.x, 100)
  assert.equal(other.x, 200)
  assert.ok(other.vx > 12)
  assert.equal(held.dragging, true)
})
test('viewport contacts use actual scaled dimensions without padding', () => {
  const a = body(390, 70)
  keepInside(a, { width: 120, height: 60 }, { left: 0, top: 80, right: 400, bottom: 300 })
  assert.equal(a.x, 340)
  assert.equal(a.y, 110)
})
test('zone centers and scale follow the available area', () => {
  const safe = zoneCenter('safe', 1000, 120, 800)
  const unsafe = zoneCenter('unsafe', 1000, 120, 800)
  const review = zoneCenter('review', 1000, 120, 800)
  assert.ok(safe.x < review.x && review.x < unsafe.x)
  assert.equal(review.y, safe.y)
  assert.equal(unsafe.y, safe.y)
  assert.ok(Math.abs(safe.x - 1000 / 6) < 0.001)
  assert.equal(zoneScale(safe.x, safe.y, safe, 1000, 680), 1)
  assert.ok(zoneScale(0, 0, safe, 1000, 680) < 1)
})
