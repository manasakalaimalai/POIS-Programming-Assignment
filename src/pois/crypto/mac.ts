/**
 * Message Authentication Codes (MAC) — PA#5
 *
 * 1. PRF-MAC (fixed-length):  Mac(k, m) = F_k(m),  Vrfy(k, m, t) = (F_k(m) === t)
 * 2. CBC-MAC (variable-length): chain F_k over 16-byte blocks with IV = 0
 * 3. HMAC stub (due PA#10)
 * 4. MAC => PRF backward direction
 * 5. EUF-CMA forgery game
 */

import { makeAesPRF, makeGgmPRF } from './prf'
import { makeAesGgmSplitPrg } from './prg'
import type { PrimitiveOracle } from '../types'

// ── Helpers ──────────────────────────────────────────────────────────────────

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length)
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i]
  }
  return out
}

// ── 1. PRF-MAC (fixed-length) ───────────────────────────────────────────────

/**
 * PRF-MAC: Mac(k, m) = F_k(m)
 * Returns the tag as a Uint8Array.
 */
export function prfMac(prf: PrimitiveOracle, message: Uint8Array): Uint8Array {
  return prf.evaluate(message)
}

/**
 * PRF-MAC verification: Vrfy(k, m, t) = (F_k(m) === t)
 */
export function prfMacVerify(
  prf: PrimitiveOracle,
  message: Uint8Array,
  tag: Uint8Array
): boolean {
  const expected = prf.evaluate(message)
  return arraysEqual(expected, tag)
}

// ── 2. CBC-MAC (variable-length) ────────────────────────────────────────────

/**
 * CBC-MAC: chain F_k over 16-byte blocks.
 *   Split message into 16-byte blocks (zero-pad last block if needed).
 *   z = 0^16
 *   For each block M_i: z = F_k(z XOR M_i)
 *   Tag = z
 */
export function cbcMac(prf: PrimitiveOracle, message: Uint8Array): Uint8Array {
  const blockSize = 16
  // Determine number of blocks (at least 1)
  const numBlocks = Math.max(1, Math.ceil(message.length / blockSize))

  // Pad message to fill full blocks
  const padded = new Uint8Array(numBlocks * blockSize)
  padded.set(message)

  let z = new Uint8Array(blockSize) // IV = 0^16

  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * blockSize, (i + 1) * blockSize)
    const input = xorBytes(z, block)
    z = new Uint8Array(prf.evaluate(input))
  }

  return z
}

/**
 * CBC-MAC verification.
 */
export function cbcMacVerify(
  prf: PrimitiveOracle,
  message: Uint8Array,
  tag: Uint8Array
): boolean {
  const expected = cbcMac(prf, message)
  return arraysEqual(expected, tag)
}

// ── 3. HMAC stub ────────────────────────────────────────────────────────────

/**
 * HMAC — not yet implemented; due PA#10.
 */
export function hmac(_key: Uint8Array, _message: Uint8Array): Uint8Array {
  throw new Error('HMAC: due PA#10')
}

// ── 4. MAC => PRF backward direction ────────────────────────────────────────

/**
 * Demonstrates that a secure MAC can serve as a PRF:
 * when queried on uniformly random inputs, the output is
 * indistinguishable from random. Wraps a MAC function as a
 * PrimitiveOracle so it can be fed into the PRF distinguishing game.
 */
export function makePRFFromMAC(
  macFn: (prf: PrimitiveOracle, msg: Uint8Array) => Uint8Array,
  prf: PrimitiveOracle
): PrimitiveOracle {
  return {
    evaluate(input: Uint8Array): Uint8Array {
      return macFn(prf, input)
    },
  }
}

// ── 5. EUF-CMA Forgery Game ─────────────────────────────────────────────────

export interface SignedPair {
  message: Uint8Array
  messageHex: string
  tag: Uint8Array
  tagHex: string
}

export interface ForgeryResult {
  accepted: boolean
  reason: string
}

/**
 * Create a MAC signing oracle for the EUF-CMA game.
 * Returns a sign function and a verify-forgery function.
 */
export function createEufCmaGame(
  prf: PrimitiveOracle,
  macType: 'prf-mac' | 'cbc-mac'
) {
  const signedMessages = new Set<string>()

  const macFn = macType === 'prf-mac' ? prfMac : cbcMac

  function sign(message: Uint8Array): Uint8Array {
    const tag = macFn(prf, message)
    // Record the hex of the message as "queried"
    const msgHex = Array.from(message)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    signedMessages.add(msgHex)
    return tag
  }

  function verifyForgery(message: Uint8Array, tag: Uint8Array): ForgeryResult {
    const msgHex = Array.from(message)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    // Check: message must not have been previously signed
    if (signedMessages.has(msgHex)) {
      return {
        accepted: false,
        reason: 'Message was already queried to the signing oracle — not a valid forgery.',
      }
    }

    // Check: tag must be valid
    const verifyFn = macType === 'prf-mac' ? prfMacVerify : cbcMacVerify
    const valid = verifyFn(prf, message, tag)

    if (!valid) {
      return {
        accepted: false,
        reason: 'Tag is invalid — MAC verification failed.',
      }
    }

    return {
      accepted: true,
      reason: 'Forgery accepted! (This should not happen with a secure MAC.)',
    }
  }

  return { sign, verifyForgery }
}

// ── Factory helpers for UI ──────────────────────────────────────────────────

export function buildPRF(prfType: 'aes' | 'ggm', keyBytes: Uint8Array): PrimitiveOracle {
  if (prfType === 'aes') {
    return makeAesPRF(keyBytes)
  }
  const prg = makeAesGgmSplitPrg()
  return makeGgmPRF(prg, keyBytes)
}
