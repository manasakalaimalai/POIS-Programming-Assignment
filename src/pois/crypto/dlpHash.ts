/**
 * PA#8 — DLP-Based Collision-Resistant Hash Function
 *
 * Compression function h(x, y) = g^x * hhat^y mod p plugged into
 * the PA#7 Merkle-Damgard framework.  Finding a collision in h
 * implies solving DLP, so h is collision-resistant under the DLP assumption.
 *
 * Includes a birthday sort attack on truncated output to demonstrate
 * the O(2^(n/2)) birthday bound.
 */

import { DLP_P, DLP_G, bytesToBigint, bigintToBytes } from './dlp'
import { merkleDamgardHash, merkleDamgardWithTrace, type MdTrace } from './merkleDamgard'

// ── Group setup ─────────────────────────────────────────────────────────────

/** Subgroup order q = (p-1)/2 */
export const DLP_Q: bigint = (DLP_P - 1n) / 2n

/**
 * Second generator: hhat = g^alpha mod p, alpha = 12345 (discarded).
 * Nobody needs to know alpha for the hash to be collision-resistant —
 * finding a collision would still require solving DLP.
 */
export const DLP_HHAT: bigint = 755995348n  // 2^12345 mod 1073741827

// ── Modular exponentiation (local copy) ─────────────────────────────────────

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n
  let result = 1n
  base = ((base % mod) + mod) % mod
  // Handle negative exponents by reducing mod (p-1)
  if (exp < 0n) {
    exp = ((exp % (mod - 1n)) + (mod - 1n)) % (mod - 1n)
  }
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod
    exp >>= 1n
    base = (base * base) % mod
  }
  return result
}

// ── DLP compression function ────────────────────────────────────────────────

/**
 * h(x, y) = g^x * hhat^y mod p
 *
 * Maps 8 bytes (4-byte chaining value || 4-byte block) to 4 bytes.
 * Collision-resistant under the DLP assumption.
 */
export function dlpCompress(chaining: Uint8Array, block: Uint8Array): Uint8Array {
  const x = bytesToBigint(chaining)
  const y = bytesToBigint(block)
  const gx = modpow(DLP_G, x, DLP_P)
  const hy = modpow(DLP_HHAT, y, DLP_P)
  const result = (gx * hy) % DLP_P
  return bigintToBytes(result, 4)
}

// ── Full DLP-based CRHF via Merkle-Damgard ──────────────────────────────────

const DLP_IV = new Uint8Array([0x00, 0x00, 0x00, 0x00])
const DLP_BLOCK_SIZE = 4

/**
 * H(message) — collision-resistant hash using DLP compression + Merkle-Damgard.
 * Output: 4 bytes.
 */
export function dlpHash(message: Uint8Array): Uint8Array {
  return merkleDamgardHash(message, dlpCompress, DLP_IV, DLP_BLOCK_SIZE)
}

/**
 * Same as dlpHash but returns full trace of chaining values for visualization.
 */
export function dlpHashWithTrace(message: Uint8Array): MdTrace {
  return merkleDamgardWithTrace(message, dlpCompress, DLP_IV, DLP_BLOCK_SIZE)
}

// ── Truncated hash for birthday demo ────────────────────────────────────────

/**
 * Truncate the DLP hash output to `bits` most-significant bits.
 * Returns the truncated value as a number.
 */
export function dlpHashTruncated(message: Uint8Array, bits: number): number {
  const digest = dlpHash(message)
  // Interpret digest as 32-bit big-endian integer
  const full = (digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]
  // Shift right to keep only the top `bits` bits (unsigned)
  return (full >>> (32 - bits))
}

// ── Birthday sort attack ────────────────────────────────────────────────────

export interface BirthdayResult {
  m1: Uint8Array
  m2: Uint8Array
  hash: number
  attempts: number
}

/**
 * Naive sort-based birthday attack on a truncated hash.
 *
 * Generates random 4-byte messages, hashes each (truncated to `bits` bits),
 * sorts by hash value, then scans for adjacent duplicates.
 *
 * Expected number of messages to find a collision: ~2^(bits/2).
 * We generate 4 * 2^(bits/2) messages to be safe.
 */
export function birthdaySortAttack(
  hashFn: (msg: Uint8Array) => number,
  bits: number,
): BirthdayResult {
  // Generate enough messages — about 4x the birthday bound
  const expected = Math.ceil(Math.pow(2, bits / 2))
  const numMessages = expected * 4

  // Build table of (hash, message) pairs
  const table: { h: number; msg: Uint8Array }[] = []
  for (let i = 0; i < numMessages; i++) {
    const msg = new Uint8Array(4)
    crypto.getRandomValues(msg)
    const h = hashFn(msg)
    table.push({ h, msg })
  }

  // Sort by hash value
  table.sort((a, b) => a.h - b.h)

  // Scan for adjacent collisions (different messages, same hash)
  for (let i = 0; i < table.length - 1; i++) {
    if (table[i].h === table[i + 1].h) {
      const a = table[i].msg
      const b = table[i + 1].msg
      // Ensure they are actually different messages
      if (a.length !== b.length || a.some((v, j) => v !== b[j])) {
        return {
          m1: a,
          m2: b,
          hash: table[i].h,
          attempts: table.length,
        }
      }
    }
  }

  // Very unlikely — try again with more messages (recursive, at most once)
  return birthdaySortAttack(hashFn, bits)
}
