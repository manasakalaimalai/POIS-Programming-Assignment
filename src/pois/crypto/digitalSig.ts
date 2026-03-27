/**
 * PA#15 — RSA Digital Signatures (Hash-then-Sign)
 *
 * Implements:
 * - RSA hash-then-sign using PA#12 RSA + PA#8 DLP hash
 * - Raw RSA signing (no hash) for forgery demonstration
 * - Multiplicative forgery on raw RSA
 * - Hash-then-sign defeats multiplicative forgery
 * - EUF-CMA security game
 */

import { modpow } from './millerRabin'
import { rsaKeygen, type RSAPublicKey, type RSAPrivateKey, type RSAKeyPair } from './rsa'
import { dlpHash } from './dlpHash'
import { bytesToBigint as dlpBytesToBigint } from './dlp'

/* ------------------------------------------------------------------ */
/*  Helper: message bytes -> hash -> bigint                            */
/* ------------------------------------------------------------------ */

/** Convert a Uint8Array message to its DLP hash as a bigint. */
export function hashToBigint(message: Uint8Array): bigint {
  const digest = dlpHash(message)
  // dlpHash returns 4 bytes; convert to bigint
  let result = 0n
  for (let i = 0; i < digest.length; i++) {
    result = (result << 8n) | BigInt(digest[i])
  }
  return result
}

/** Convert a string to Uint8Array using TextEncoder. */
export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

/* ------------------------------------------------------------------ */
/*  RSA Hash-then-Sign: sign and verify                                */
/* ------------------------------------------------------------------ */

/**
 * Sign a message using RSA hash-then-sign.
 * sigma = H(m)^d mod N
 */
export function sign(sk: RSAPrivateKey, message: Uint8Array): bigint {
  const h = hashToBigint(message)
  return modpow(h, sk.d, sk.N)
}

/**
 * Verify an RSA hash-then-sign signature.
 * Check: sigma^e mod N === H(m)
 */
export function verify(pk: RSAPublicKey, message: Uint8Array, sigma: bigint): boolean {
  const h = hashToBigint(message)
  const recovered = modpow(sigma, pk.e, pk.N)
  return recovered === h
}

/* ------------------------------------------------------------------ */
/*  Raw RSA sign (no hash) — for forgery demo                          */
/* ------------------------------------------------------------------ */

/**
 * Raw RSA signing: sigma = m^d mod N (no hashing).
 */
export function signRaw(sk: RSAPrivateKey, m: bigint): bigint {
  return modpow(m, sk.d, sk.N)
}

/**
 * Raw RSA verification: sigma^e mod N === m.
 */
export function verifyRaw(pk: RSAPublicKey, m: bigint, sigma: bigint): boolean {
  const recovered = modpow(sigma, pk.e, pk.N)
  return recovered === m
}

/* ------------------------------------------------------------------ */
/*  Multiplicative forgery on raw RSA                                  */
/* ------------------------------------------------------------------ */

export interface MultiplicativeForgeryResult {
  m1: bigint
  m2: bigint
  sigma1: bigint
  sigma2: bigint
  mForged: bigint
  sigmaForged: bigint
  forgerySucceeded: boolean
}

/**
 * Demonstrate multiplicative forgery on raw RSA signatures.
 *
 * Given signatures on m1 and m2, forge a signature on m1*m2 mod N
 * without the private key, exploiting RSA's multiplicative homomorphism.
 */
export function multiplicativeForgery(
  pk: RSAPublicKey,
  sk: RSAPrivateKey,
): MultiplicativeForgeryResult {
  // Pick two small messages
  const m1 = 42n
  const m2 = 137n

  // Get legitimate signatures
  const sigma1 = signRaw(sk, m1)
  const sigma2 = signRaw(sk, m2)

  // Forge signature on m1 * m2 mod N
  const mForged = (m1 * m2) % pk.N
  const sigmaForged = (sigma1 * sigma2) % pk.N

  // Verify the forged signature
  const forgerySucceeded = verifyRaw(pk, mForged, sigmaForged)

  return { m1, m2, sigma1, sigma2, mForged, sigmaForged, forgerySucceeded }
}

/* ------------------------------------------------------------------ */
/*  Hash-then-sign defeats forgery                                     */
/* ------------------------------------------------------------------ */

export interface HashForgeryResult {
  m1: bigint
  m2: bigint
  hm1: bigint
  hm2: bigint
  sigma1: bigint
  sigma2: bigint
  mProduct: bigint
  hProduct: bigint
  hProductOfInputs: bigint
  sigmaForged: bigint
  forgerySucceeded: boolean
}

/**
 * Show that multiplicative forgery fails with hash-then-sign.
 *
 * sigma1 * sigma2 mod N would be a valid signature on H(m1)*H(m2) mod N,
 * but the adversary needs it to verify for H(m1*m2), which is different
 * because H is not multiplicative.
 */
export function hashThenSignDefeatsForgery(
  pk: RSAPublicKey,
  sk: RSAPrivateKey,
): HashForgeryResult {
  const m1Bytes = textToBytes('message one')
  const m2Bytes = textToBytes('message two')

  const m1 = dlpBytesToBigint(m1Bytes)
  const m2 = dlpBytesToBigint(m2Bytes)

  const hm1 = hashToBigint(m1Bytes)
  const hm2 = hashToBigint(m2Bytes)

  // Legitimate signatures (hash-then-sign)
  const sigma1 = sign(sk, m1Bytes)
  const sigma2 = sign(sk, m2Bytes)

  // Adversary tries: forge signature on m1*m2
  const mProduct = (m1 * m2) % pk.N

  // sigma1 * sigma2 mod N = H(m1)^d * H(m2)^d mod N = (H(m1)*H(m2))^d mod N
  const sigmaForged = (sigma1 * sigma2) % pk.N

  // What the forged sigma actually signs for:
  const hProductOfInputs = (hm1 * hm2) % pk.N

  // What verification needs: H(m1 * m2 mod N)
  // We need to hash the product as bytes
  const productHex = mProduct.toString(16)
  const paddedHex = productHex.length % 2 === 1 ? '0' + productHex : productHex
  const productBytes = new Uint8Array(paddedHex.length / 2)
  for (let i = 0; i < productBytes.length; i++) {
    productBytes[i] = parseInt(paddedHex.slice(i * 2, i * 2 + 2), 16)
  }
  const hProduct = hashToBigint(productBytes)

  // Verification: sigmaForged^e mod N should equal H(m1*m2) for forgery to work
  // But sigmaForged^e mod N = H(m1)*H(m2) mod N != H(m1*m2) in general
  const recovered = modpow(sigmaForged, pk.e, pk.N)
  const forgerySucceeded = recovered === hProduct

  return {
    m1, m2, hm1, hm2, sigma1, sigma2,
    mProduct, hProduct, hProductOfInputs,
    sigmaForged, forgerySucceeded,
  }
}

/* ------------------------------------------------------------------ */
/*  EUF-CMA game                                                       */
/* ------------------------------------------------------------------ */

export interface EufCmaResult {
  queries: { message: string; sigma: bigint }[]
  forgeryAttempts: { message: string; sigma: bigint; valid: boolean }[]
  adversaryWon: boolean
}

/**
 * Simulate the EUF-CMA (Existential Unforgeability under Chosen Message Attack) game.
 *
 * 1. Adversary makes numQueries signing oracle queries on chosen messages.
 * 2. Adversary attempts to forge a signature on a *new* message (not queried).
 * 3. We show the adversary always fails (cannot produce valid forgery).
 */
export function eufCmaGame(
  pk: RSAPublicKey,
  sk: RSAPrivateKey,
  numQueries: number,
): EufCmaResult {
  // Phase 1: Adversary queries the signing oracle
  const queries: { message: string; sigma: bigint }[] = []
  for (let i = 0; i < numQueries; i++) {
    const msg = `query message ${i}`
    const msgBytes = textToBytes(msg)
    const sigma = sign(sk, msgBytes)
    queries.push({ message: msg, sigma })
  }

  // Phase 2: Adversary tries to forge signatures on new messages
  const forgeryAttempts: { message: string; sigma: bigint; valid: boolean }[] = []
  const newMessages = [
    'forged message attempt 1',
    'forged message attempt 2',
    'another forgery try',
  ]

  for (const msg of newMessages) {
    const msgBytes = textToBytes(msg)
    // Adversary has no private key, so tries random "signatures"
    // Use a deterministic but incorrect value
    const fakeSigma = hashToBigint(msgBytes) + 1n
    const valid = verify(pk, msgBytes, fakeSigma)
    forgeryAttempts.push({ message: msg, sigma: fakeSigma, valid })
  }

  const adversaryWon = forgeryAttempts.some(a => a.valid)

  return { queries, forgeryAttempts, adversaryWon }
}

/* ------------------------------------------------------------------ */
/*  Re-export key generation for convenience                           */
/* ------------------------------------------------------------------ */

export { rsaKeygen, type RSAPublicKey, type RSAPrivateKey, type RSAKeyPair }
