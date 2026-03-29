/**
 * PA#3 — CPA-Secure Symmetric Encryption
 *
 * Construction: C = ⟨r, F_k(r) ⊕ m⟩
 *   - r is sampled fresh and uniformly for each encryption
 *   - F_k is the PRF from PA#2 (GGM or AES plug-in)
 *
 * Multi-block support: for messages longer than one block (16 bytes),
 * apply PRF to r, r+1, r+2, … (counter-based extension).
 *
 * Broken variant: deterministic encryption reuses a fixed r, demonstrating
 * that nonce reuse catastrophically breaks CPA security.
 */

import type { PrimitiveOracle } from '../types'

const BLOCK_SIZE = 16

/** XOR two byte arrays of equal length */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i]
  }
  return out
}

/** Increment a 16-byte counter (big-endian) by 1 */
function incrementCounter(ctr: Uint8Array): Uint8Array {
  const out = Uint8Array.from(ctr)
  for (let i = out.length - 1; i >= 0; i--) {
    out[i] = (out[i] + 1) & 0xff
    if (out[i] !== 0) break // no carry
  }
  return out
}

/** PKCS#7 padding: pad to block boundary */
function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE)
  const out = new Uint8Array(data.length + padLen)
  out.set(data)
  out.fill(padLen, data.length)
  return out
}

/** PKCS#7 unpadding */
function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error('Invalid padded data length')
  }
  const padLen = data[data.length - 1]
  if (padLen === 0 || padLen > BLOCK_SIZE) {
    throw new Error('Invalid padding')
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('Invalid padding')
  }
  return data.slice(0, data.length - padLen)
}

/** Generate cryptographically random bytes (OS-level randomness allowed per spec) */
function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  crypto.getRandomValues(out)
  return out
}

/**
 * CPA-secure encryption: Enc(k, m) -> (r, c)
 *
 * @param prfOracle - F_k (PRF keyed with k, from PA#2)
 * @param message - plaintext bytes
 * @param fixedNonce - if provided, use this instead of random r (BROKEN/deterministic mode)
 * @returns { r, ciphertext } where ciphertext = F_k(r) ⊕ m_1 || F_k(r+1) ⊕ m_2 || ...
 */
export function cpaEncrypt(
  prfOracle: PrimitiveOracle,
  message: Uint8Array,
  fixedNonce?: Uint8Array
): { r: Uint8Array; ciphertext: Uint8Array } {
  const padded = pkcs7Pad(message)
  const numBlocks = padded.length / BLOCK_SIZE
  const r = fixedNonce ? new Uint8Array(fixedNonce) : randomBytes(BLOCK_SIZE)

  const ciphertext = new Uint8Array(padded.length)
  let counter: Uint8Array = new Uint8Array(r)

  for (let i = 0; i < numBlocks; i++) {
    const prfOut = prfOracle.evaluate(counter)
    const block = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const encBlock = xorBytes(prfOut.slice(0, BLOCK_SIZE), block)
    ciphertext.set(encBlock, i * BLOCK_SIZE)
    counter = incrementCounter(counter)
  }

  return { r, ciphertext }
}

/**
 * CPA-secure decryption: Dec(k, r, c) -> m
 *
 * @param prfOracle - F_k (same PRF used for encryption)
 * @param r - the nonce from the ciphertext
 * @param ciphertext - encrypted data
 * @returns plaintext bytes (unpadded)
 */
export function cpaDecrypt(
  prfOracle: PrimitiveOracle,
  r: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  const numBlocks = Math.ceil(ciphertext.length / BLOCK_SIZE)
  const padded = new Uint8Array(numBlocks * BLOCK_SIZE)

  let counter: Uint8Array = new Uint8Array(r)

  for (let i = 0; i < numBlocks; i++) {
    const prfOut = prfOracle.evaluate(counter)
    const block = ciphertext.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    // Handle last block potentially being shorter
    const decBlock = xorBytes(prfOut.slice(0, BLOCK_SIZE), block.length < BLOCK_SIZE
      ? (() => { const b = new Uint8Array(BLOCK_SIZE); b.set(block); return b })()
      : block)
    padded.set(decBlock, i * BLOCK_SIZE)
    counter = incrementCounter(counter)
  }

  return pkcs7Unpad(padded)
}

/**
 * IND-CPA game simulation.
 *
 * The challenger picks a random bit b, encrypts m_b, and the adversary guesses b.
 * Returns whether the adversary's guess was correct.
 */
export function indCpaChallenge(
  prfOracle: PrimitiveOracle,
  m0: Uint8Array,
  m1: Uint8Array,
  reuseNonce: boolean
): {
  b: number
  challengeCiphertext: { r: Uint8Array; ciphertext: Uint8Array }
} {
  const b = reuseNonce ? 0 : (crypto.getRandomValues(new Uint8Array(1))[0] & 1)

  const fixedNonce = reuseNonce
    ? new Uint8Array(BLOCK_SIZE).fill(0x42) // deterministic r
    : undefined

  const challengeCiphertext = cpaEncrypt(
    prfOracle,
    b === 0 ? m0 : m1,
    fixedNonce
  )

  return { b, challengeCiphertext }
}

/**
 * Demonstrate nonce reuse attack:
 * Encrypt m0 and m1 with the same nonce; XOR ciphertexts to get m0 ⊕ m1.
 */
export function nonceReuseAttack(
  prfOracle: PrimitiveOracle,
  m0: Uint8Array,
  m1: Uint8Array
): {
  c0: { r: Uint8Array; ciphertext: Uint8Array }
  c1: { r: Uint8Array; ciphertext: Uint8Array }
  xorCiphertexts: Uint8Array
  xorPlaintexts: Uint8Array
  match: boolean
} {
  const nonce = new Uint8Array(BLOCK_SIZE).fill(0x42)
  const c0 = cpaEncrypt(prfOracle, m0, nonce)
  const c1 = cpaEncrypt(prfOracle, m1, nonce)

  const minLen = Math.min(c0.ciphertext.length, c1.ciphertext.length)
  const xorCiphertexts = xorBytes(
    c0.ciphertext.slice(0, minLen),
    c1.ciphertext.slice(0, minLen)
  )

  const pad0 = pkcs7Pad(m0)
  const pad1 = pkcs7Pad(m1)
  const minPadLen = Math.min(pad0.length, pad1.length)
  const xorPlaintexts = xorBytes(
    pad0.slice(0, minPadLen),
    pad1.slice(0, minPadLen)
  )

  // Check that XOR of ciphertexts equals XOR of plaintexts (proves nonce reuse leaks)
  const match = xorCiphertexts.length === xorPlaintexts.length &&
    xorCiphertexts.every((b, i) => b === xorPlaintexts[i])

  return { c0, c1, xorCiphertexts, xorPlaintexts, match }
}
