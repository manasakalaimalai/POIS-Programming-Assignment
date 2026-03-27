/**
 * Pseudorandom Generator (PRG) — HILL hard-core-bit construction.
 *
 * Given OWF f and hard-core predicate b, define:
 *   G(x0) = b(x0) || b(x1) || ... || b(x_{ℓ-1})
 *   where x_{i+1} = f(x_i)
 *
 * Hard-core predicate: b(x) = LSB of f(x) (least significant bit of OWF output).
 */

import type { ByteArray, PrimitiveOracle } from '../types'
import { aes128 } from './aes128'

/**
 * Generate `outputLen` bytes of pseudorandom output from `seed`
 * using the HILL construction over the given OWF oracle.
 *
 * Collects one hardcore bit per OWF call; packs bits MSB-first.
 */
export function hillGenerate(
  owfOracle: PrimitiveOracle,
  seed: ByteArray,
  outputLen: number
): ByteArray {
  const totalBits = outputLen * 8
  const out = new Uint8Array(outputLen)

  let x: ByteArray = new Uint8Array(seed)
  for (let bit = 0; bit < totalBits; bit++) {
    x = owfOracle.evaluate(x)
    const hardcoreBit = x[x.length - 1] & 1   // LSB of OWF output
    const byteIdx = Math.floor(bit / 8)
    const bitIdx = 7 - (bit % 8)               // MSB-first packing
    if (hardcoreBit) out[byteIdx] |= (1 << bitIdx)
  }

  return out
}

/**
 * PRG oracle adapter: evaluate(seed) = G(seed) via HILL construction.
 * Output length = seed.length * expansionFactor (default 2×).
 */
export function makePRGOracle(
  owfOracle: PrimitiveOracle,
  expansionFactor = 2
): PrimitiveOracle {
  return {
    evaluate(seed: ByteArray): ByteArray {
      const outLen = Math.max(seed.length * expansionFactor, 16)
      return hillGenerate(owfOracle, seed, outLen)
    },
  }
}

/**
 * Fast AES-based PRG for GGM tree visualization.
 * G(v) = AES_v(0^128) || AES_v(1^128) — just 2 AES calls, output = 32 bytes.
 * Much cheaper than the HILL construction (128 OWF calls) and correct for
 * GGM tree demos where we split each node into two children.
 */
export function makeAesGgmSplitPrg(): PrimitiveOracle {
  const ones = new Uint8Array(16).fill(0xff)
  return {
    evaluate(nodeValue: ByteArray): ByteArray {
      const k = new Uint8Array(16)
      k.set(nodeValue.slice(0, 16))
      const left  = aes128(k, new Uint8Array(16))  // AES_k(0^128)
      const right = aes128(k, ones)                 // AES_k(1^128)
      const out = new Uint8Array(32)
      out.set(left)
      out.set(right, 16)
      return out
    },
  }
}

/**
 * OWF-from-PRG (backward direction, PA#1b):
 * f(s) = G(s), truncated back to seed length.
 * Hard to invert because inverting f would break the PRG.
 */
export function makeOwfFromPRGOracle(prgOracle: PrimitiveOracle): PrimitiveOracle {
  return {
    evaluate(seed: ByteArray): ByteArray {
      const expanded = prgOracle.evaluate(seed)
      return expanded.slice(0, seed.length)
    },
  }
}
