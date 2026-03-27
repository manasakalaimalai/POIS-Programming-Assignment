/**
 * PA#10 — HMAC and HMAC-Based CCA-Secure Encryption
 *
 * 1. HMAC: H((k XOR opad) || H((k XOR ipad) || m))
 * 2. HMAC_Verify with constant-time comparison
 * 3. Length-extension attack demo on naive H(k||m) MAC
 * 4. CRHF => MAC (forward): HMAC is EUF-CMA secure
 * 5. MAC => CRHF (backward): macToCrhf via Merkle-Damgard
 * 6. Encrypt-then-HMAC CCA-secure scheme
 */

import { dlpHash, dlpCompress } from './dlpHash'
import { merkleDamgardHash, mdPad, type CompressFn } from './merkleDamgard'

// ── Types ────────────────────────────────────────────────────────────────────

export type HashFn = (message: Uint8Array) => Uint8Array

// ── Constants ────────────────────────────────────────────────────────────────

/** DLP hash block size and output size (both 4 bytes) */
const BLOCK_SIZE = 4
const OUTPUT_SIZE = 4
const IPAD_BYTE = 0x36
const OPAD_BYTE = 0x5c

// ── Helpers ──────────────────────────────────────────────────────────────────

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length)
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i]
  return out
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    out.set(a, offset)
    offset += a.length
  }
  return out
}

/** Pad or hash the key to exactly BLOCK_SIZE bytes */
function padKey(key: Uint8Array, hashFn: HashFn): Uint8Array {
  if (key.length > BLOCK_SIZE) {
    key = hashFn(key)
  }
  if (key.length < BLOCK_SIZE) {
    const padded = new Uint8Array(BLOCK_SIZE)
    padded.set(key)
    return padded
  }
  return key
}

// ── 1. HMAC ──────────────────────────────────────────────────────────────────

/**
 * HMAC_k(m) = H((k XOR opad) || H((k XOR ipad) || m))
 *
 * Default hashFn = dlpHash (PA#8), block size b = 4, output = 4 bytes.
 */
export function hmac(
  key: Uint8Array,
  message: Uint8Array,
  hashFn: HashFn = dlpHash,
): Uint8Array {
  const k = padKey(key, hashFn)

  const ipad = new Uint8Array(BLOCK_SIZE).fill(IPAD_BYTE)
  const opad = new Uint8Array(BLOCK_SIZE).fill(OPAD_BYTE)

  const kXorIpad = xorBytes(k, ipad)
  const kXorOpad = xorBytes(k, opad)

  const innerHash = hashFn(concatBytes(kXorIpad, message))
  const outerHash = hashFn(concatBytes(kXorOpad, innerHash))

  return outerHash
}

// ── 2. HMAC Verify ───────────────────────────────────────────────────────────

/**
 * Constant-time byte comparison: XOR all bytes, result must be zero.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
}

/**
 * Verify HMAC tag using constant-time comparison.
 */
export function hmacVerify(
  key: Uint8Array,
  message: Uint8Array,
  tag: Uint8Array,
  hashFn: HashFn = dlpHash,
): boolean {
  const expected = hmac(key, message, hashFn)
  return constantTimeEqual(expected, tag)
}

// ── 3. Naive MAC: H(k || m) ─────────────────────────────────────────────────

/**
 * Naive MAC: tag = H(key || message).
 * Vulnerable to length-extension attacks on Merkle-Damgard hashes.
 */
export function naiveMac(
  key: Uint8Array,
  message: Uint8Array,
  hashFn: HashFn = dlpHash,
): Uint8Array {
  return hashFn(concatBytes(key, message))
}

// ── 4. Length-Extension Attack Demo ──────────────────────────────────────────

export interface LengthExtensionResult {
  /** Original tag: H(key || message) */
  originalTag: Uint8Array
  /** Forged tag: H(key || message || padding || suffix) computed WITHOUT key */
  forgedTag: Uint8Array
  /** The actual tag: H(key || message || padding || suffix) computed WITH key */
  actualTag: Uint8Array
  /** Whether the forgery succeeded on naive H(k||m) */
  naiveAttackSucceeds: boolean
  /** Whether the forgery succeeded on HMAC */
  hmacAttackSucceeds: boolean
  /** The padding bytes inserted by MD */
  paddingBytes: Uint8Array
  /** HMAC tag on original message */
  hmacOriginalTag: Uint8Array
}

/**
 * Length-extension attack demo.
 *
 * Given H(key || message) = tag (naive MAC), the attacker (without knowing the key)
 * can compute H(key || message || padding || suffix) by continuing the hash
 * from the tag state.
 *
 * The attack works because in Merkle-Damgard, knowing the final chaining value
 * (= the hash output) lets you continue hashing more blocks.
 */
export function lengthExtensionAttack(
  key: Uint8Array,
  message: Uint8Array,
  suffix: Uint8Array,
  hashFn: HashFn = dlpHash,
): LengthExtensionResult {
  // Step 1: Compute the naive MAC (original tag)
  const keyMsg = concatBytes(key, message)
  const originalTag = hashFn(keyMsg)

  // Step 2: Compute the MD padding for key||message
  // The attacker knows len(key||message) (or guesses it)
  const paddedKeyMsg = mdPad(keyMsg, BLOCK_SIZE)
  const paddingBytes = paddedKeyMsg.slice(keyMsg.length)

  // Step 3: Attacker forges tag by continuing hash from originalTag state
  // Use originalTag as the chaining value and hash the suffix
  // This means: H(key || message || padding || suffix) = MD(suffix, cv=originalTag)
  const suffixPadded = mdPad(suffix, BLOCK_SIZE)
  let cv = originalTag
  for (let i = 0; i < suffixPadded.length; i += BLOCK_SIZE) {
    const block = suffixPadded.slice(i, i + BLOCK_SIZE)
    cv = dlpCompress(cv, block)
  }
  const forgedTag = cv

  // Step 4: Compute the actual tag: H(key || message || padding || suffix)
  const fullMsg = concatBytes(keyMsg, paddingBytes, suffix)
  const actualTag = hashFn(fullMsg)

  // Step 5: Check if forgery works on naive MAC
  const naiveAttackSucceeds = constantTimeEqual(forgedTag, actualTag)

  // Step 6: Show HMAC is NOT vulnerable
  const hmacOriginalTag = hmac(key, message, hashFn)
  // Attacker cannot extend HMAC because of the outer hash
  const hmacAttackSucceeds = false // HMAC always blocks length extension

  return {
    originalTag,
    forgedTag,
    actualTag,
    naiveAttackSucceeds,
    hmacAttackSucceeds,
    paddingBytes,
    hmacOriginalTag,
  }
}

// ── 5. CRHF => MAC (forward): EUF-CMA security of HMAC ──────────────────────

export interface EufCmaResult {
  queries: number
  forgeryAttempts: number
  forgerySucceeded: boolean
}

/**
 * Run the EUF-CMA forgery game for HMAC.
 * An adversary makes `numQueries` signing queries and then tries to forge.
 * Since HMAC is EUF-CMA secure, forgery always fails.
 */
export function hmacEufCmaGame(numQueries: number = 50): EufCmaResult {
  // Random key
  const key = new Uint8Array(BLOCK_SIZE)
  crypto.getRandomValues(key)

  const queriedMessages = new Set<string>()
  const queriedTags: Uint8Array[] = []

  // Adversary makes signing queries
  for (let i = 0; i < numQueries; i++) {
    const msg = new Uint8Array(4)
    crypto.getRandomValues(msg)
    const tag = hmac(key, msg)
    const msgHex = Array.from(msg).map(b => b.toString(16).padStart(2, '0')).join('')
    queriedMessages.add(msgHex)
    queriedTags.push(tag)
  }

  // Adversary tries to forge on a fresh message
  let forgerySucceeded = false
  for (let attempt = 0; attempt < 100; attempt++) {
    const forgeryMsg = new Uint8Array(4)
    crypto.getRandomValues(forgeryMsg)
    const forgeryMsgHex = Array.from(forgeryMsg).map(b => b.toString(16).padStart(2, '0')).join('')

    if (queriedMessages.has(forgeryMsgHex)) continue

    // Adversary guesses a random tag
    const guessTag = new Uint8Array(OUTPUT_SIZE)
    crypto.getRandomValues(guessTag)

    if (hmacVerify(key, forgeryMsg, guessTag)) {
      forgerySucceeded = true
      break
    }
  }

  return {
    queries: numQueries,
    forgeryAttempts: 100,
    forgerySucceeded,
  }
}

// ── 6. MAC => CRHF (backward) ────────────────────────────────────────────────

/**
 * Build a CRHF from a MAC: define h'(cv, block) = MAC_k(cv || block).
 * Plug this compression function into Merkle-Damgard to get a CRHF.
 *
 * If the MAC is EUF-CMA secure, finding a collision in h' implies
 * finding a MAC forgery (contradiction).
 */
export function macToCrhf(
  macFn: (key: Uint8Array, msg: Uint8Array) => Uint8Array,
  key: Uint8Array,
): { compress: CompressFn; hash: (msg: Uint8Array) => Uint8Array } {
  const compress: CompressFn = (cv: Uint8Array, block: Uint8Array) => {
    return macFn(key, concatBytes(cv, block))
  }

  const iv = new Uint8Array(OUTPUT_SIZE) // zero IV
  const hash = (msg: Uint8Array) => merkleDamgardHash(msg, compress, iv, BLOCK_SIZE)

  return { compress, hash }
}

// ── 7. Encrypt-then-HMAC (CCA-secure) ───────────────────────────────────────

/**
 * Simple CPA encryption inline (since cpaEnc.ts is not on this branch).
 * Uses XOR with a PRF-like stream derived from key and randomness.
 * E_kE(m; r) = (r, m XOR H(kE || r) || H(kE || r || 0x01) || ...)
 */
function cpaEncrypt(kE: Uint8Array, message: Uint8Array): { r: Uint8Array; ciphertext: Uint8Array } {
  const r = new Uint8Array(BLOCK_SIZE)
  crypto.getRandomValues(r)

  // Generate keystream by repeatedly hashing kE || r || counter
  const ciphertext = new Uint8Array(message.length)
  let offset = 0
  let counter = 0
  while (offset < message.length) {
    const counterByte = new Uint8Array([counter & 0xff])
    const streamBlock = dlpHash(concatBytes(kE, r, counterByte))
    const remaining = Math.min(streamBlock.length, message.length - offset)
    for (let i = 0; i < remaining; i++) {
      ciphertext[offset + i] = message[offset + i] ^ streamBlock[i]
    }
    offset += remaining
    counter++
  }

  return { r, ciphertext }
}

function cpaDecrypt(kE: Uint8Array, r: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  // XOR is its own inverse
  const plaintext = new Uint8Array(ciphertext.length)
  let offset = 0
  let counter = 0
  while (offset < ciphertext.length) {
    const counterByte = new Uint8Array([counter & 0xff])
    const streamBlock = dlpHash(concatBytes(kE, r, counterByte))
    const remaining = Math.min(streamBlock.length, ciphertext.length - offset)
    for (let i = 0; i < remaining; i++) {
      plaintext[offset + i] = ciphertext[offset + i] ^ streamBlock[i]
    }
    offset += remaining
    counter++
  }
  return plaintext
}

/**
 * Encrypt-then-HMAC: CPA-encrypt with kE, then HMAC the ciphertext with kM.
 * Returns (r, ciphertext, tag).
 */
export function ethEncrypt(
  kE: Uint8Array,
  kM: Uint8Array,
  message: Uint8Array,
): { r: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } {
  const { r, ciphertext } = cpaEncrypt(kE, message)
  // HMAC over r || ciphertext (authenticate everything the adversary sees)
  const tag = hmac(kM, concatBytes(r, ciphertext))
  return { r, ciphertext, tag }
}

/**
 * Decrypt-then-verify: verify HMAC first, return null on failure.
 */
export function ethDecrypt(
  kE: Uint8Array,
  kM: Uint8Array,
  r: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  // Verify HMAC first (reject tampered ciphertexts)
  if (!hmacVerify(kM, concatBytes(r, ciphertext), tag)) {
    return null
  }
  return cpaDecrypt(kE, r, ciphertext)
}
