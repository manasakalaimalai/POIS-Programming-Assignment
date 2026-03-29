/**
 * PA#11 — Diffie-Hellman Key Exchange
 *
 * Implements:
 * - DH key exchange over a safe prime group (toy parameters ~30 bits)
 * - MITM attack demonstration
 * - CDH brute-force hardness demo
 *
 * Uses modpow and randomBigInt from PA#13 Miller-Rabin.
 */

import { modpow, randomBigInt } from './millerRabin'

/* ------------------------------------------------------------------ */
/*  Group parameters                                                   */
/* ------------------------------------------------------------------ */

// Safe prime p = 1_073_741_827, q = (p-1)/2 = 536_870_913
// Generator g = 2 generates the subgroup of order q
const p = 1_073_741_827n
const q = (p - 1n) / 2n // 536_870_913n
const g = 2n

export const DH_PARAMS = { p, g, q }

/* ------------------------------------------------------------------ */
/*  Helper: random exponent in [2, q-1]                                */
/* ------------------------------------------------------------------ */

function randomExponent(): bigint {
  // q is about 30 bits; generate random values and use rejection sampling
  const bits = 30
  for (;;) {
    const r = randomBigInt(bits) % q
    if (r >= 2n) return r
  }
}

/* ------------------------------------------------------------------ */
/*  DH protocol functions                                              */
/* ------------------------------------------------------------------ */

export type DHStep1 = { secret: bigint; public: bigint }

/** Alice samples a random private exponent a, computes A = g^a mod p. */
export function dhAliceStep1(): DHStep1 {
  const a = randomExponent()
  const A = modpow(g, a, p)
  return { secret: a, public: A }
}

/** Bob samples a random private exponent b, computes B = g^b mod p. */
export function dhBobStep1(): DHStep1 {
  const b = randomExponent()
  const B = modpow(g, b, p)
  return { secret: b, public: B }
}

/** Alice computes shared secret K = B^a mod p. */
export function dhAliceStep2(a: bigint, B: bigint): bigint {
  return modpow(B, a, p)
}

/** Bob computes shared secret K = A^b mod p. */
export function dhBobStep2(b: bigint, A: bigint): bigint {
  return modpow(A, b, p)
}

/* ------------------------------------------------------------------ */
/*  MITM attack                                                        */
/* ------------------------------------------------------------------ */

export type MITMResult = {
  e: bigint
  aPrime: bigint // g^e mod p — sent to Bob as fake "Alice's public key"
  bPrime: bigint // g^e mod p — sent to Alice as fake "Bob's public key"
  kAliceEve: bigint // A^e mod p — shared secret between Alice and Eve
  kBobEve: bigint   // B^e mod p — shared secret between Bob and Eve
}

/**
 * Eve intercepts A (from Alice) and B (from Bob).
 * She picks her own secret e, and computes substitute values.
 * Eve then shares a secret with Alice and a separate secret with Bob.
 */
export function mitmAttack(A: bigint, B: bigint): MITMResult {
  const e = randomExponent()
  const aPrime = modpow(g, e, p) // sent to Bob
  const bPrime = modpow(g, e, p) // sent to Alice
  const kAliceEve = modpow(A, e, p) // K = A^e = g^(ae) mod p
  const kBobEve = modpow(B, e, p)   // K = B^e = g^(be) mod p
  return { e, aPrime, bPrime, kAliceEve, kBobEve }
}

/* ------------------------------------------------------------------ */
/*  CDH brute-force demo                                               */
/* ------------------------------------------------------------------ */

export type CDHBruteResult = {
  gab: bigint
  attempts: number
  timeMs: number
}

/**
 * Given g^a and g^b (mod p), brute-force the CDH problem by trying
 * all possible values of a until g^a matches, then compute (g^b)^a.
 * Only feasible for small group orders.
 */
export function cdhBruteForce(gA: bigint, gB: bigint): CDHBruteResult {
  const start = performance.now()
  let attempts = 0

  for (let tryA = 2n; tryA < q; tryA++) {
    attempts++
    if (modpow(g, tryA, p) === gA) {
      // Found a such that g^a = gA, now compute g^(ab) = gB^a
      const gab = modpow(gB, tryA, p)
      const timeMs = performance.now() - start
      return { gab, attempts, timeMs }
    }
  }

  // Should not reach here for valid inputs
  return { gab: 0n, attempts, timeMs: performance.now() - start }
}

/* ------------------------------------------------------------------ */
/*  Display helper                                                     */
/* ------------------------------------------------------------------ */

/** Convert a BigInt to a hex string for display. */
export function bigintToHex(n: bigint): string {
  if (n < 0n) return '-' + bigintToHex(-n)
  const hex = n.toString(16)
  return hex.length % 2 === 0 ? '0x' + hex : '0x0' + hex
}
