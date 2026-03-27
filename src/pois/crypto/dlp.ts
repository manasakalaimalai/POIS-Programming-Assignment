/**
 * DLP-based One-Way Function — scratch implementation.
 * f(x) = g^x mod p where p is a toy safe prime (~30 bits).
 * Uses JavaScript's native BigInt for arbitrary-precision arithmetic.
 */

import type { ByteArray } from '../types'

// Safe prime: p = 1_073_741_827, (p-1)/2 = 536_870_913 (also prime)
// Generator g = 2 generates the subgroup of order (p-1)/2
export const DLP_P: bigint = 1_073_741_827n
export const DLP_G: bigint = 2n

/** Convert a ByteArray to a non-negative BigInt (big-endian). */
export function bytesToBigint(b: ByteArray): bigint {
  let n = 0n
  for (const byte of b) {
    n = (n << 8n) | BigInt(byte)
  }
  return n
}

/** Encode a BigInt into a fixed-size big-endian ByteArray. */
export function bigintToBytes(n: bigint, size: number): ByteArray {
  const out = new Uint8Array(size)
  let v = n < 0n ? -n : n
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/**
 * DLP OWF: f(x) = g^x mod p
 * Input: arbitrary bytes interpreted as a big-endian integer exponent.
 * Output: 4-byte big-endian encoding of the result (p < 2^30, fits in 4 bytes).
 */
export function dlpOwfEval(xBytes: ByteArray): ByteArray {
  const x = bytesToBigint(xBytes) % (DLP_P - 1n)  // exponent in Z_{p-1}
  const result = modpow(DLP_G, x, DLP_P)
  return bigintToBytes(result, 4)
}

/**
 * Hard-core predicate for DLP: LSB of (g^x mod p).
 * This is computationally hard to predict given only g^x mod p.
 */
export function dlpHardcoreBit(xBytes: ByteArray): 0 | 1 {
  const out = dlpOwfEval(xBytes)
  return (out[3] & 1) as 0 | 1
}

/** Modular exponentiation: base^exp mod mod (BigInt). */
function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n
  let result = 1n
  base = base % mod
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod
    exp >>= 1n
    base = (base * base) % mod
  }
  return result
}
