/**
 * One-Way Function oracle factories.
 * Provides two concrete OWF instantiations:
 *   1. AES Davies-Meyer: f(k) = AES_k(0^128) XOR k
 *   2. DLP-based:        f(x) = g^x mod p
 */

import type { ByteArray, PrimitiveOracle } from '../types'
import { aes128 } from './aes128'
import { dlpOwfEval } from './dlp'

const ZERO_BLOCK = new Uint8Array(16)

/**
 * AES Davies-Meyer OWF: f(k) = AES_k(0^128) XOR k
 * Input must be 16 bytes (zero-padded if shorter).
 */
export function aesDaviesMeyerOwfEval(kBytes: ByteArray): ByteArray {
  const k = new Uint8Array(16)
  k.set(kBytes.slice(0, 16))
  const enc = aes128(k, ZERO_BLOCK)
  for (let i = 0; i < 16; i++) enc[i] ^= k[i]
  return enc
}

/** PrimitiveOracle wrapping AES Davies-Meyer OWF. */
export function makeAesOwfOracle(): PrimitiveOracle {
  return {
    evaluate(input: ByteArray): ByteArray {
      // Pad/truncate input to 16 bytes as the "key" k
      const k = new Uint8Array(16)
      k.set(input.slice(0, 16))
      return aesDaviesMeyerOwfEval(k)
    },
  }
}

/**
 * PrimitiveOracle wrapping DLP OWF: f(x) = g^x mod p.
 * Output is 4 bytes (big-endian); zero-padded to 16 bytes for uniformity.
 */
export function makeDlpOwfOracle(): PrimitiveOracle {
  return {
    evaluate(input: ByteArray): ByteArray {
      const raw = dlpOwfEval(input)  // 4 bytes
      const out = new Uint8Array(16)
      out.set(raw, 12)               // right-align in 16-byte block
      return out
    },
  }
}
