/**
 * PA#6 — CCA-Secure Symmetric Encryption via Encrypt-then-MAC
 *
 * Combines PA#3 CPA-Enc with PA#5 CBC-MAC to achieve CCA2 security.
 * Construction: Encrypt-then-MAC with key separation (kE, kM).
 *
 * Demonstrates:
 *   1. CCA-secure encryption/decryption
 *   2. IND-CCA2 game simulation
 *   3. CPA malleability attack (bit-flipping)
 *   4. CCA blocks malleability (MAC detects tampering)
 *   5. Constant-time tag comparison
 */

import { makeAesPRF } from './prf'
import { cpaEncrypt, cpaDecrypt } from './cpaEnc'
import { cbcMac, cbcMacVerify } from './mac'

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Concatenate two Uint8Arrays */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a)
  out.set(b, a.length)
  return out
}

/**
 * Constant-time comparison of two Uint8Arrays.
 * Avoids timing side-channels: always iterates over all bytes.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
}

// ── CCA-Secure Encryption (Encrypt-then-MAC) ────────────────────────────────

/**
 * CCA-secure encryption: Encrypt-then-MAC.
 *
 * 1. Encrypt with CPA scheme using kE
 * 2. MAC the full ciphertext (r || ct) using kM
 * 3. Return (r, ciphertext, tag)
 */
export function ccaEncrypt(
  kE: Uint8Array,
  kM: Uint8Array,
  message: Uint8Array
): { r: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } {
  const prfE = makeAesPRF(kE)
  const prfM = makeAesPRF(kM)

  const { r, ciphertext } = cpaEncrypt(prfE, message)
  const tag = cbcMac(prfM, concat(r, ciphertext))

  return { r, ciphertext, tag }
}

/**
 * CCA-secure decryption: verify MAC then decrypt.
 *
 * 1. Verify tag over (r || ciphertext) using kM
 * 2. If invalid, return null (reject)
 * 3. If valid, decrypt using kE and return plaintext
 */
export function ccaDecrypt(
  kE: Uint8Array,
  kM: Uint8Array,
  r: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Uint8Array | null {
  const prfE = makeAesPRF(kE)
  const prfM = makeAesPRF(kM)

  // Verify MAC
  const valid = cbcMacVerify(prfM, concat(r, ciphertext), tag)
  if (!valid) return null

  // Decrypt
  return cpaDecrypt(prfE, r, ciphertext)
}

// ── IND-CCA2 Game Simulation ─────────────────────────────────────────────────

/**
 * IND-CCA2 challenge: challenger picks random b, encrypts m_b.
 * The adversary also gets a decryption oracle that rejects the challenge ciphertext.
 */
export function indCca2Challenge(
  kE: Uint8Array,
  kM: Uint8Array,
  m0: Uint8Array,
  m1: Uint8Array
): {
  b: number
  challengeCiphertext: { r: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array }
  decryptionOracle: (r: Uint8Array, ct: Uint8Array, tag: Uint8Array) => Uint8Array | null
} {
  const b = crypto.getRandomValues(new Uint8Array(1))[0] & 1
  const challengeCt = ccaEncrypt(kE, kM, b === 0 ? m0 : m1)

  // Decryption oracle: rejects the challenge ciphertext
  const decryptionOracle = (r: Uint8Array, ct: Uint8Array, tag: Uint8Array): Uint8Array | null => {
    // Reject if this is the challenge ciphertext
    if (
      constantTimeEqual(r, challengeCt.r) &&
      constantTimeEqual(ct, challengeCt.ciphertext) &&
      constantTimeEqual(tag, challengeCt.tag)
    ) {
      return null // Reject challenge ciphertext
    }
    return ccaDecrypt(kE, kM, r, ct, tag)
  }

  return { b, challengeCiphertext: challengeCt, decryptionOracle }
}

// ── Malleability Attack on CPA-Only ──────────────────────────────────────────

/**
 * Demonstrate CPA malleability: encrypt, flip a bit in ciphertext, decrypt.
 * Because CPA has no integrity, the bit flip in ciphertext produces a
 * corresponding bit flip in the plaintext.
 */
export function cpaMalleabilityAttack(
  kE: Uint8Array,
  message: Uint8Array,
  bitIndex = 0
): {
  originalPlaintext: Uint8Array
  r: Uint8Array
  originalCiphertext: Uint8Array
  modifiedCiphertext: Uint8Array
  decryptedModified: Uint8Array
  bitFlipped: number
} {
  const prfE = makeAesPRF(kE)
  const { r, ciphertext } = cpaEncrypt(prfE, message)

  // Flip bit at bitIndex in the ciphertext
  const byteIdx = Math.floor(bitIndex / 8) % ciphertext.length
  const bitIdx = bitIndex % 8
  const modified = new Uint8Array(ciphertext)
  modified[byteIdx] ^= (1 << bitIdx)

  // Decrypt the modified ciphertext (CPA has no integrity check)
  const decryptedModified = cpaDecrypt(prfE, r, modified)

  return {
    originalPlaintext: message,
    r,
    originalCiphertext: ciphertext,
    modifiedCiphertext: modified,
    decryptedModified,
    bitFlipped: bitIndex,
  }
}

// ── Malleability Blocked by CCA ──────────────────────────────────────────────

/**
 * Same bit-flip attack, but on CCA (Encrypt-then-MAC).
 * MAC verification fails, so decryption returns null.
 */
export function ccaMalleabilityBlocked(
  kE: Uint8Array,
  kM: Uint8Array,
  message: Uint8Array,
  bitIndex = 0
): {
  r: Uint8Array
  originalCiphertext: Uint8Array
  tag: Uint8Array
  modifiedCiphertext: Uint8Array
  decryptResult: Uint8Array | null
  bitFlipped: number
} {
  const { r, ciphertext, tag } = ccaEncrypt(kE, kM, message)

  // Flip bit at bitIndex in the ciphertext
  const byteIdx = Math.floor(bitIndex / 8) % ciphertext.length
  const bitIdx = bitIndex % 8
  const modified = new Uint8Array(ciphertext)
  modified[byteIdx] ^= (1 << bitIdx)

  // Attempt decryption — MAC verification should fail
  const decryptResult = ccaDecrypt(kE, kM, r, modified, tag)

  return {
    r,
    originalCiphertext: ciphertext,
    tag,
    modifiedCiphertext: modified,
    decryptResult,
    bitFlipped: bitIndex,
  }
}
