/**
 * PA#14 — Chinese Remainder Theorem & Hastad's Broadcast Attack
 *
 * Implements:
 * - CRT solver for arbitrary pairwise coprime moduli
 * - RSA-CRT decryption (Garner's algorithm)
 * - Performance benchmark: standard RSA vs RSA-CRT
 * - Integer nth root via Newton's method
 * - Hastad's broadcast attack on textbook RSA (e=3)
 * - Demo showing PKCS#1 v1.5 padding defeats the attack
 */

import { modpow } from './millerRabin'
import {
  modInverse,
  rsaEncrypt,
  rsaDecrypt,
  pkcs1v15Pad,
  type RSAKeyPair,
  type RSAPrivateKey,
} from './rsa'

/* ------------------------------------------------------------------ */
/*  Chinese Remainder Theorem                                          */
/* ------------------------------------------------------------------ */

/**
 * Given residues a_i and pairwise coprime moduli n_i, compute the
 * unique x in [0, N) such that x === a_i (mod n_i) for all i,
 * where N = product of all n_i.
 */
export function crt(residues: bigint[], moduli: bigint[]): bigint {
  if (residues.length !== moduli.length || residues.length === 0) {
    throw new Error('residues and moduli must be non-empty arrays of equal length')
  }

  const k = residues.length
  let N = 1n
  for (let i = 0; i < k; i++) {
    N *= moduli[i]
  }

  let x = 0n
  for (let i = 0; i < k; i++) {
    const Ni = N / moduli[i]
    const yi = modInverse(Ni, moduli[i])
    x = (x + residues[i] * Ni % N * yi) % N
  }

  return ((x % N) + N) % N
}

/* ------------------------------------------------------------------ */
/*  RSA-CRT Decryption (Garner's Algorithm)                            */
/* ------------------------------------------------------------------ */

export type RSACrtKey = {
  p: bigint
  q: bigint
  d: bigint
  dp: bigint
  dq: bigint
  qinv: bigint
  N: bigint
}

/**
 * Decrypt ciphertext c using CRT-based RSA decryption.
 *
 * m_p = c^dp mod p
 * m_q = c^dq mod q
 * h   = qinv * (m_p - m_q) mod p
 * m   = m_q + h * q
 */
export function rsaDecCrt(sk: RSACrtKey, c: bigint): bigint {
  const mp = modpow(c, sk.dp, sk.p)
  const mq = modpow(c, sk.dq, sk.q)
  const diff = ((mp - mq) % sk.p + sk.p) % sk.p
  const h = (sk.qinv * diff) % sk.p
  const m = mq + h * sk.q
  return m % sk.N
}

/* ------------------------------------------------------------------ */
/*  Performance Benchmark                                              */
/* ------------------------------------------------------------------ */

export type BenchmarkResult = {
  standardMs: number
  crtMs: number
  speedup: number
}

/**
 * Compare standard RSA decryption vs CRT decryption.
 */
export function benchmarkCrt(keys: RSAKeyPair, numTrials: number): BenchmarkResult {
  // Encrypt a test message
  const m = 42n
  const c = rsaEncrypt({ N: keys.N, e: keys.e }, m)

  const standardSk: RSAPrivateKey = { N: keys.N, d: keys.d }
  const crtSk: RSACrtKey = {
    p: keys.p,
    q: keys.q,
    d: keys.d,
    dp: keys.dp,
    dq: keys.dq,
    qinv: keys.qinv,
    N: keys.N,
  }

  // Warm up
  rsaDecrypt(standardSk, c)
  rsaDecCrt(crtSk, c)

  // Standard RSA
  const t0 = performance.now()
  for (let i = 0; i < numTrials; i++) {
    rsaDecrypt(standardSk, c)
  }
  const t1 = performance.now()

  // CRT RSA
  const t2 = performance.now()
  for (let i = 0; i < numTrials; i++) {
    rsaDecCrt(crtSk, c)
  }
  const t3 = performance.now()

  const standardMs = t1 - t0
  const crtMs = t3 - t2
  const speedup = crtMs > 0 ? standardMs / crtMs : Infinity

  return { standardMs, crtMs, speedup }
}

/* ------------------------------------------------------------------ */
/*  Integer Nth Root (Newton's Method)                                 */
/* ------------------------------------------------------------------ */

/**
 * Compute floor(x^(1/n)) for positive x and n >= 2 using Newton's method.
 */
export function integerNthRoot(x: bigint, n: number): bigint {
  if (x <= 0n) return 0n
  if (n === 1) return x
  if (x === 1n) return 1n

  const bn = BigInt(n)

  // Initial guess: use bit length to estimate
  const bitLen = x.toString(2).length
  const guessBits = Math.ceil(bitLen / n) + 1
  let r = 1n << BigInt(guessBits)

  // Newton's iteration: r' = ((n-1)*r + x / r^(n-1)) / n
  for (let iter = 0; iter < 1000; iter++) {
    // Compute r^(n-1)
    let rPow = 1n
    for (let i = 1; i < n; i++) {
      rPow *= r
    }
    const rNext = ((bn - 1n) * r + x / rPow) / bn
    if (rNext >= r) break
    r = rNext
  }

  // Verify and adjust: ensure r^n <= x < (r+1)^n
  // Check r+1 in case we undershot
  let rPlusOnePow = 1n
  for (let i = 0; i < n; i++) {
    rPlusOnePow *= (r + 1n)
  }
  if (rPlusOnePow <= x) {
    r = r + 1n
  }

  return r
}

/* ------------------------------------------------------------------ */
/*  Hastad's Broadcast Attack                                          */
/* ------------------------------------------------------------------ */

/**
 * Hastad's broadcast attack: given e ciphertexts encrypted under
 * different RSA moduli with public exponent e, recover the plaintext.
 *
 * 1. Use CRT to find x = m^e mod (N1 * N2 * ... * Ne)
 * 2. Since m < each Ni, m^e < N1*N2*...*Ne, so x = m^e exactly
 * 3. Compute m = floor(x^(1/e))
 */
export function hastadAttack(
  ciphertexts: bigint[],
  moduli: bigint[],
  e: number,
): bigint {
  const x = crt(ciphertexts, moduli)
  const m = integerNthRoot(x, e)
  return m
}

/* ------------------------------------------------------------------ */
/*  Hastad Demo (e=3, three recipients)                                */
/* ------------------------------------------------------------------ */

export type HastadDemoResult = {
  keys: { N: bigint; e: bigint }[]
  ciphertexts: bigint[]
  crtResult: bigint
  recoveredMessage: bigint
  originalMessage: bigint
  attackSucceeded: boolean
}

/**
 * Generate 3 RSA key pairs with e=3 and demonstrate Hastad's attack.
 */
export function hastadDemo(message: bigint, bits: number): HastadDemoResult {
  // Generate 3 key pairs with e=3
  const keyPairs: RSAKeyPair[] = []
  for (let i = 0; i < 3; i++) {
    keyPairs.push(rsaKeygenE3(bits))
  }

  const publicKeys = keyPairs.map(k => ({ N: k.N, e: k.e }))
  const moduli = keyPairs.map(k => k.N)

  // Encrypt same message with each key
  const ciphertexts = publicKeys.map(pk => rsaEncrypt(pk, message))

  // Run CRT
  const crtResult = crt(ciphertexts, moduli)

  // Cube root
  const recoveredMessage = integerNthRoot(crtResult, 3)

  return {
    keys: publicKeys,
    ciphertexts,
    crtResult,
    recoveredMessage,
    originalMessage: message,
    attackSucceeded: recoveredMessage === message,
  }
}

/* ------------------------------------------------------------------ */
/*  Hastad with Padding (attack fails)                                 */
/* ------------------------------------------------------------------ */

export type HastadPaddingResult = {
  keys: { N: bigint; e: bigint }[]
  paddedValues: bigint[]
  ciphertexts: bigint[]
  crtResult: bigint
  recoveredValue: bigint
  originalMessage: bigint
  attackSucceeded: boolean
}

/**
 * Same as hastadDemo but with PKCS#1 v1.5 padding.
 * The random padding makes each padded value different,
 * so CRT + cube root does NOT recover the original message.
 */
export function hastadWithPadding(
  message: Uint8Array,
  bits: number,
): HastadPaddingResult {
  const keyPairs: RSAKeyPair[] = []
  for (let i = 0; i < 3; i++) {
    keyPairs.push(rsaKeygenE3(bits))
  }

  const publicKeys = keyPairs.map(k => ({ N: k.N, e: k.e }))
  const moduli = keyPairs.map(k => k.N)

  // Pad message (each padding is random, so padded values differ)
  const paddedValues: bigint[] = []
  const ciphertexts: bigint[] = []
  for (const pk of publicKeys) {
    const keyBytes = Math.ceil(pk.N.toString(2).length / 8)
    const padded = pkcs1v15Pad(message, keyBytes)
    paddedValues.push(padded)
    ciphertexts.push(rsaEncrypt(pk, padded))
  }

  const crtResult = crt(ciphertexts, moduli)
  const recoveredValue = integerNthRoot(crtResult, 3)

  // Convert original message bytes to bigint for comparison
  let origBigint = 0n
  for (let i = 0; i < message.length; i++) {
    origBigint = (origBigint << 8n) | BigInt(message[i])
  }

  return {
    keys: publicKeys,
    paddedValues,
    ciphertexts,
    crtResult,
    recoveredValue,
    originalMessage: origBigint,
    attackSucceeded: recoveredValue === origBigint,
  }
}

/* ------------------------------------------------------------------ */
/*  RSA key generation with e=3                                        */
/* ------------------------------------------------------------------ */

import { genPrime } from './millerRabin'
import { extgcd } from './rsa'

/**
 * Generate RSA key pair with e=3.
 * p and q must satisfy p !== 1 (mod 3) and q !== 1 (mod 3),
 * i.e., gcd(3, (p-1)(q-1)) = 1.
 */
function rsaKeygenE3(bits: number): RSAKeyPair {
  const halfBits = Math.floor(bits / 2)
  const e = 3n

  let p: bigint, q: bigint, phi: bigint
  for (;;) {
    p = genPrime(halfBits).prime
    // Ensure p mod 3 !== 1 (so gcd(3, p-1) = 1)
    if ((p - 1n) % 3n === 0n) continue
    q = genPrime(halfBits).prime
    if (p === q) continue
    if ((q - 1n) % 3n === 0n) continue
    phi = (p - 1n) * (q - 1n)
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
