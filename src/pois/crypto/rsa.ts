/**
 * PA#12 — Textbook RSA and PKCS#1 v1.5
 *
 * Implements:
 * - Extended GCD and modular inverse
 * - RSA key generation (using PA#13 genPrime)
 * - Textbook RSA encrypt/decrypt
 * - PKCS#1 v1.5 padding/unpadding and encrypt/decrypt
 * - Determinism attack demo
 * - Simplified Bleichenbacher padding oracle demo
 */

import { modpow, genPrime, randomBigInt } from './millerRabin'

/* ------------------------------------------------------------------ */
/*  BigInt <-> Bytes conversion helpers                                */
/* ------------------------------------------------------------------ */

export function bigintToBytes(n: bigint, len: number): Uint8Array {
  const bytes = new Uint8Array(len)
  let val = n
  for (let i = len - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return bytes
}

export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i])
  }
  return result
}

/* ------------------------------------------------------------------ */
/*  Extended Euclidean Algorithm                                       */
/* ------------------------------------------------------------------ */

export function extgcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  if (b === 0n) {
    return { g: a, x: 1n, y: 0n }
  }
  const { g, x: x1, y: y1 } = extgcd(b, a % b)
  return { g, x: y1, y: x1 - (a / b) * y1 }
}

export function modInverse(a: bigint, m: bigint): bigint {
  const { g, x } = extgcd(a, m)
  if (g !== 1n) {
    throw new Error('Modular inverse does not exist')
  }
  return ((x % m) + m) % m
}

/* ------------------------------------------------------------------ */
/*  RSA Key Types                                                      */
/* ------------------------------------------------------------------ */

export type RSAPublicKey = { N: bigint; e: bigint }
export type RSAPrivateKey = { N: bigint; d: bigint }
export type RSAKeyPair = {
  p: bigint
  q: bigint
  N: bigint
  e: bigint
  d: bigint
  dp: bigint
  dq: bigint
  qinv: bigint
}

/* ------------------------------------------------------------------ */
/*  RSA Key Generation                                                 */
/* ------------------------------------------------------------------ */

export function rsaKeygen(bits: number): RSAKeyPair {
  const halfBits = Math.floor(bits / 2)
  const e = 65537n

  // Generate p and q such that gcd(e, phi) = 1
  let p: bigint, q: bigint, phi: bigint
  for (;;) {
    p = genPrime(halfBits).prime
    q = genPrime(halfBits).prime
    // Ensure p != q
    if (p === q) continue
    phi = (p - 1n) * (q - 1n)
    // Ensure e is coprime with phi
    const { g } = extgcd(e, phi)
    if (g === 1n) break
  }

  const N = p * q
  const d = modInverse(e, phi)
  const dp = d % (p - 1n)
  const dq = d % (q - 1n)
  const qinv = modInverse(q, p)

  return { p, q, N, e, d, dp, dq, qinv }
}

/* ------------------------------------------------------------------ */
/*  Textbook RSA Encrypt / Decrypt                                     */
/* ------------------------------------------------------------------ */

export function rsaEncrypt(pk: RSAPublicKey, m: bigint): bigint {
  return modpow(m, pk.e, pk.N)
}

export function rsaDecrypt(sk: RSAPrivateKey, c: bigint): bigint {
  return modpow(c, sk.d, sk.N)
}

/* ------------------------------------------------------------------ */
/*  PKCS#1 v1.5 Padding                                               */
/* ------------------------------------------------------------------ */

export function pkcs1v15Pad(message: Uint8Array, keyBytes: number): bigint {
  // EM = 0x00 || 0x02 || PS || 0x00 || message
  // |PS| >= 8, all nonzero random bytes
  const psLen = keyBytes - message.length - 3
  if (psLen < 8) {
    throw new Error('Message too long for key size')
  }

  const em = new Uint8Array(keyBytes)
  em[0] = 0x00
  em[1] = 0x02

  // Fill PS with random nonzero bytes
  for (let i = 2; i < 2 + psLen; i++) {
    let b = 0
    while (b === 0) {
      const tmp = new Uint8Array(1)
      crypto.getRandomValues(tmp)
      b = tmp[0]
    }
    em[i] = b
  }

  em[2 + psLen] = 0x00
  em.set(message, 3 + psLen)

  return bytesToBigint(em)
}

export function pkcs1v15Unpad(em: bigint, keyBytes: number): Uint8Array | null {
  const bytes = bigintToBytes(em, keyBytes)

  // Check format: 0x00 || 0x02 || PS || 0x00 || M
  if (bytes[0] !== 0x00 || bytes[1] !== 0x02) {
    return null
  }

  // Find the 0x00 separator after PS (PS must be >= 8 nonzero bytes)
  let sepIdx = -1
  for (let i = 2; i < bytes.length; i++) {
    if (bytes[i] === 0x00) {
      sepIdx = i
      break
    }
  }

  // PS must be at least 8 bytes (indices 2..9 must be nonzero, separator at index >= 10)
  if (sepIdx < 10) {
    return null
  }

  return bytes.slice(sepIdx + 1)
}

/* ------------------------------------------------------------------ */
/*  PKCS#1 v1.5 Encrypt / Decrypt                                     */
/* ------------------------------------------------------------------ */

export function pkcs15Encrypt(pk: RSAPublicKey, message: Uint8Array): bigint {
  const keyBytes = Math.ceil(pk.N.toString(2).length / 8)
  const padded = pkcs1v15Pad(message, keyBytes)
  return rsaEncrypt(pk, padded)
}

export function pkcs15Decrypt(
  sk: RSAPrivateKey,
  c: bigint,
  keyBytes: number,
): Uint8Array | null {
  const em = rsaDecrypt(sk, c)
  return pkcs1v15Unpad(em, keyBytes)
}

/* ------------------------------------------------------------------ */
/*  Determinism Attack Demo                                            */
/* ------------------------------------------------------------------ */

export type DeterminismResult = {
  textbookC1: bigint
  textbookC2: bigint
  textbookMatch: boolean
  pkcs15C1: bigint
  pkcs15C2: bigint
  pkcs15Match: boolean
}

export function determinismAttack(
  pk: RSAPublicKey,
  m: bigint,
): DeterminismResult {
  // Textbook RSA: same plaintext -> same ciphertext (deterministic)
  const textbookC1 = rsaEncrypt(pk, m)
  const textbookC2 = rsaEncrypt(pk, m)

  // PKCS#1 v1.5: same plaintext -> different ciphertext (randomized padding)
  const mBytes = bigintToBytes(m, Math.ceil(m.toString(2).length / 8) || 1)
  const pkcs15C1 = pkcs15Encrypt(pk, mBytes)
  const pkcs15C2 = pkcs15Encrypt(pk, mBytes)

  return {
    textbookC1,
    textbookC2,
    textbookMatch: textbookC1 === textbookC2,
    pkcs15C1,
    pkcs15C2,
    pkcs15Match: pkcs15C1 === pkcs15C2,
  }
}

/* ------------------------------------------------------------------ */
/*  Bleichenbacher Padding Oracle (simplified demo)                    */
/* ------------------------------------------------------------------ */

export function paddingOracle(
  sk: RSAPrivateKey,
  c: bigint,
  keyBytes: number,
): boolean {
  const em = rsaDecrypt(sk, c)
  const bytes = bigintToBytes(em, keyBytes)
  // Valid PKCS#1 v1.5: starts with 0x00 0x02
  if (bytes[0] !== 0x00 || bytes[1] !== 0x02) return false
  // Must have a 0x00 separator after at least 8 bytes of PS
  for (let i = 2; i < bytes.length; i++) {
    if (bytes[i] === 0x00) {
      return i >= 10 // PS must be >= 8 bytes
    }
  }
  return false
}

export type BleichenbacherDemoResult = {
  originalValid: boolean
  tamperedCiphertexts: { c: bigint; s: bigint; oracleResult: boolean }[]
  infoLeaked: boolean
}

export function bleichenbacherDemo(
  pk: RSAPublicKey,
  sk: RSAPrivateKey,
  c: bigint,
  keyBytes: number,
): BleichenbacherDemoResult {
  const originalValid = paddingOracle(sk, c, keyBytes)

  // Demonstrate that multiplying ciphertext by s^e mod N and querying oracle
  // leaks information about the plaintext.
  const tamperedCiphertexts: { c: bigint; s: bigint; oracleResult: boolean }[] = []

  for (let i = 0; i < 10; i++) {
    const s = randomBigInt(Math.max(16, Math.floor(keyBytes * 2)))
    // RSA homomorphism: (c * s^e) mod N decrypts to (m * s) mod N
    const sEnc = modpow(s, pk.e, pk.N)
    const tamperedC = (c * sEnc) % pk.N
    const result = paddingOracle(sk, tamperedC, keyBytes)
    tamperedCiphertexts.push({ c: tamperedC, s, oracleResult: result })
  }

  // If the oracle gives different answers for different tampered ciphertexts,
  // information is leaked about the plaintext.
  const results = tamperedCiphertexts.map((t) => t.oracleResult)
  const hasTrue = results.some((r) => r)
  const hasFalse = results.some((r) => !r)
  const infoLeaked = hasTrue && hasFalse

  return { originalValid, tamperedCiphertexts, infoLeaked }
}
