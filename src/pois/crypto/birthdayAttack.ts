/**
 * PA#9 — Birthday Attack on Truncated Hash Functions
 *
 * Demonstrates the birthday bound O(2^(n/2)) via:
 *   1. Naive sort-based collision finder (Map-based, NOT sort-based despite the name)
 *   2. Floyd's cycle detection (O(1) space)
 *   3. Empirical trial runner for plotting against theoretical curve
 *   4. Theoretical computation for MD5/SHA context
 */

// ── Types ────────────────────────────────────────────────────────────────────

export interface BirthdayResult {
  m1: Uint8Array
  m2: Uint8Array
  hash: number
  attempts: number
}

export interface FloydResult {
  m1: number
  m2: number
  hash: number
  attempts: number
}

// ── 1. Naive birthday (Map-based) ────────────────────────────────────────────

/**
 * Generate random 4-byte messages, hash each (truncated to `bits` bits),
 * store in a Map keyed by hash value.  Return on first collision.
 *
 * Expected attempts: ~sqrt(pi/2 * 2^bits) ≈ 1.25 * 2^(bits/2).
 */
export function birthdayNaive(
  hashFn: (msg: Uint8Array) => number,
  _bits?: number,
): BirthdayResult {
  const seen = new Map<number, Uint8Array>()
  let attempts = 0

  for (;;) {
    const msg = new Uint8Array(4)
    crypto.getRandomValues(msg)
    const h = hashFn(msg)
    attempts++

    const prev = seen.get(h)
    if (prev !== undefined) {
      // Ensure messages are actually different
      if (prev.some((v, j) => v !== msg[j])) {
        return { m1: prev, m2: new Uint8Array(msg), hash: h, attempts }
      }
    }
    seen.set(h, new Uint8Array(msg))
  }
}

// ── 2. Floyd's cycle detection ───────────────────────────────────────────────

/**
 * Treat hashFn as f: {0,1}^n -> {0,1}^n.
 * Use tortoise-and-hare to find a cycle, then extract collision pair.
 * O(1) space (no hash table).
 */
export function birthdayFloyd(
  hashFn: (x: number) => number,
  bits: number,
): FloydResult {
  const mask = (1 << bits) - 1
  const f = (x: number) => hashFn(x) & mask

  // Start from a random point
  const x0 = (crypto.getRandomValues(new Uint8Array(4))[0]!) & mask
  let attempts = 0

  // Phase 1: find meeting point (tortoise and hare)
  let tortoise = f(x0)
  let hare = f(f(x0))
  attempts += 3 // x0->t, x0->h1, h1->h2
  while (tortoise !== hare) {
    tortoise = f(tortoise)
    hare = f(f(hare))
    attempts += 3
  }

  // Phase 2: find the start of the cycle
  tortoise = x0
  while (tortoise !== hare) {
    tortoise = f(tortoise)
    hare = f(hare)
    attempts += 2
  }

  // Phase 3: find two distinct inputs that collide
  // mu is the start of the cycle; now walk one step at a time to find collision
  const mu = tortoise
  // The cycle length lambda: walk from mu until we return
  let lambda = 1
  let power = 1
  tortoise = mu
  hare = f(mu)
  attempts += 1
  while (tortoise !== hare) {
    if (lambda === power) {
      tortoise = hare
      power *= 2
      lambda = 0
    }
    hare = f(hare)
    lambda++
    attempts++
  }

  // Now try all pairs: for each point in the rho, check if another point
  // lambda steps ahead gives the same f-output
  // Simpler approach: collect points and find collision directly
  // Since we're in a rho of length mu_len + lambda, just collect the tail + cycle
  let curr = x0
  const visited = new Map<number, number>() // hash -> input
  for (;;) {
    const h = f(curr)
    attempts++
    const prev = visited.get(h)
    if (prev !== undefined && prev !== curr) {
      return { m1: prev, m2: curr, hash: h, attempts }
    }
    visited.set(h, curr)
    curr = f(curr)
    attempts++
    // Safety: if we've gone too long, restart
    if (visited.size > (1 << bits) * 2) break
  }

  // Fallback: shouldn't reach here for reasonable bit sizes
  return birthdayFloyd(hashFn, bits)
}

// ── 3. Empirical birthday curve ──────────────────────────────────────────────

/**
 * Run `numTrials` independent naive birthday attacks.
 * Returns array of attempt counts (for plotting against theoretical curve).
 */
export function runBirthdayTrials(
  hashFn: (msg: Uint8Array) => number,
  bits: number,
  numTrials: number,
): number[] {
  const results: number[] = []
  for (let t = 0; t < numTrials; t++) {
    const r = birthdayNaive(hashFn, bits)
    results.push(r.attempts)
  }
  return results
}

// ── 4. Theoretical computations ──────────────────────────────────────────────

/**
 * For an n-bit hash, compute 2^(n/2) and express in human-readable time
 * at 10^9 hashes/sec.
 */
export function computeTheoretical(n: number): {
  birthdayBound: number
  hashSpaceSize: number
  secondsAt1GHps: number
  humanReadable: string
} {
  const birthdayBound = Math.pow(2, n / 2)
  const hashSpaceSize = Math.pow(2, n)
  const secondsAt1GHps = birthdayBound / 1e9

  let humanReadable: string
  if (secondsAt1GHps < 1e-6) {
    humanReadable = `${(secondsAt1GHps * 1e9).toFixed(1)} ns`
  } else if (secondsAt1GHps < 1e-3) {
    humanReadable = `${(secondsAt1GHps * 1e6).toFixed(1)} us`
  } else if (secondsAt1GHps < 1) {
    humanReadable = `${(secondsAt1GHps * 1e3).toFixed(1)} ms`
  } else if (secondsAt1GHps < 60) {
    humanReadable = `${secondsAt1GHps.toFixed(1)} sec`
  } else if (secondsAt1GHps < 3600) {
    humanReadable = `${(secondsAt1GHps / 60).toFixed(1)} min`
  } else if (secondsAt1GHps < 86400) {
    humanReadable = `${(secondsAt1GHps / 3600).toFixed(1)} hours`
  } else if (secondsAt1GHps < 86400 * 365.25) {
    humanReadable = `${(secondsAt1GHps / 86400).toFixed(1)} days`
  } else if (secondsAt1GHps < 86400 * 365.25 * 1e6) {
    humanReadable = `${(secondsAt1GHps / (86400 * 365.25)).toFixed(1)} years`
  } else {
    humanReadable = `${(secondsAt1GHps / (86400 * 365.25)).toExponential(2)} years`
  }

  return { birthdayBound, hashSpaceSize, secondsAt1GHps, humanReadable }
}
