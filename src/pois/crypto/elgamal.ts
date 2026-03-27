/**
 * PA#16 — ElGamal Public-Key Cryptosystem
 *
 * Implements:
 * - Key generation over DH group from PA#11
 * - Encryption and decryption
 * - Malleability attack demonstration
 * - IND-CPA game simulation
 *
 * Uses modpow and randomBigInt from PA#13 Miller-Rabin,
 * and DH_PARAMS from PA#11 Diffie-Hellman.
 */

import { modpow, randomBigInt } from './millerRabin'
import { DH_PARAMS } from './diffieHellman'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type ElGamalPublicKey = {
  p: bigint
  g: bigint
  q: bigint
  h: bigint
}

export type ElGamalKeyPair = {
  sk: bigint
  pk: ElGamalPublicKey
}

export type ElGamalCiphertext = {
  c1: bigint
  c2: bigint
}

export type MalleabilityResult = {
  original: bigint
  c1: bigint
  c2: bigint
  modifiedC2: bigint
  decryptedModified: bigint
  expected: bigint
  match: boolean
}

export type CpaGameResult = {
  m0: bigint
  m1: bigint
  b: number
  ciphertext: ElGamalCiphertext
  adversaryGuess: number
  correct: boolean
}

/* ------------------------------------------------------------------ */
/*  Helper: random exponent in [2, q-1]                                */
/* ------------------------------------------------------------------ */

function randomExponent(): bigint {
  const { q } = DH_PARAMS
  const bits = 30
  for (;;) {
    const r = randomBigInt(bits) % q
    if (r >= 2n) return r
  }
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                     */
/* ------------------------------------------------------------------ */

export function elgamalKeygen(): ElGamalKeyPair {
  const { p, g, q } = DH_PARAMS
  const x = randomExponent()           // private key x in [2, q-1]
  const h = modpow(g, x, p)            // public key h = g^x mod p
  return { sk: x, pk: { p, g, q, h } }
}

/* ------------------------------------------------------------------ */
/*  Encryption                                                         */
/* ------------------------------------------------------------------ */

export function elgamalEncrypt(pk: ElGamalPublicKey, m: bigint): ElGamalCiphertext {
  const { p, g, h } = pk
  if (m < 1n || m >= p) {
    throw new Error(`Message m must be in [1, p-1]. Got ${m}`)
  }
  const r = randomExponent()            // random r in [2, q-1]
  const c1 = modpow(g, r, p)           // c1 = g^r mod p
  const c2 = (m * modpow(h, r, p)) % p // c2 = m * h^r mod p
  return { c1, c2 }
}

/* ------------------------------------------------------------------ */
/*  Decryption                                                         */
/* ------------------------------------------------------------------ */

export function elgamalDecrypt(
  sk: bigint,
  pk: ElGamalPublicKey,
  c1: bigint,
  c2: bigint,
): bigint {
  const { p } = pk
  const s = modpow(c1, sk, p)          // shared secret s = c1^x mod p
  const sInv = modpow(s, p - 2n, p)    // s^{-1} via Fermat's little theorem
  return (c2 * sInv) % p               // m = c2 * s^{-1} mod p
}

/* ------------------------------------------------------------------ */
/*  Malleability attack                                                */
/* ------------------------------------------------------------------ */

export function elgamalMalleability(
  pk: ElGamalPublicKey,
  sk: bigint,
  m: bigint,
): MalleabilityResult {
  const { p } = pk
  const { c1, c2 } = elgamalEncrypt(pk, m)

  // Multiply c2 by 2 — produces a valid ciphertext for 2m
  const modifiedC2 = (2n * c2) % p

  // Decrypt the modified ciphertext
  const decryptedModified = elgamalDecrypt(sk, pk, c1, modifiedC2)
  const expected = (2n * m) % p

  return {
    original: m,
    c1,
    c2,
    modifiedC2,
    decryptedModified,
    expected,
    match: decryptedModified === expected,
  }
}

/* ------------------------------------------------------------------ */
/*  IND-CPA game                                                       */
/* ------------------------------------------------------------------ */

export function elgamalCpaGame(
  pk: ElGamalPublicKey,
  _sk: bigint,
  m0: bigint,
  m1: bigint,
): CpaGameResult {
  // Challenger picks random bit b
  const b = crypto.getRandomValues(new Uint8Array(1))[0] & 1
  const mb = b === 0 ? m0 : m1

  // Encrypt m_b
  const ciphertext = elgamalEncrypt(pk, mb)

  // Adversary guesses randomly (no info leakage from ciphertext)
  const adversaryGuess = crypto.getRandomValues(new Uint8Array(1))[0] & 1

  return {
    m0,
    m1,
    b,
    ciphertext,
    adversaryGuess,
    correct: adversaryGuess === b,
  }
}

/* ------------------------------------------------------------------ */
/*  Display helper                                                     */
/* ------------------------------------------------------------------ */

export function bigintToHex(n: bigint): string {
  if (n < 0n) return '-' + bigintToHex(-n)
  const hex = n.toString(16)
  return hex.length % 2 === 0 ? '0x' + hex : '0x0' + hex
}
