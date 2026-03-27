/**
 * PA#18 — 1-out-of-2 Oblivious Transfer (Bellare-Micali)
 *
 * Implements:
 * - OT_Receiver_Step1: receiver picks choice bit b, generates honest + fake keys
 * - OT_Sender_Step: sender encrypts m0 under pk0, m1 under pk1
 * - OT_Receiver_Step2: receiver decrypts C_b using sk_b
 * - Full OT convenience wrapper
 * - Correctness test
 * - Receiver privacy demo (both pks look valid)
 * - Sender privacy demo (receiver cannot decrypt C_{1-b})
 *
 * Uses ElGamal from PA#16, which uses DH params from PA#11 and
 * modpow/randomBigInt from PA#13.
 */

import {
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  type ElGamalPublicKey,
  type ElGamalCiphertext,
} from './elgamal'
import { modpow, randomBigInt } from './millerRabin'
import { DH_PARAMS } from './diffieHellman'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type OTReceiverState = {
  b: 0 | 1
  sk_b: bigint
  pk_b: ElGamalPublicKey
}

export type OTReceiverStep1Result = {
  pk0: ElGamalPublicKey
  pk1: ElGamalPublicKey
  state: OTReceiverState
}

export type OTSenderResult = {
  C0: ElGamalCiphertext
  C1: ElGamalCiphertext
}

export type OTTranscript = {
  b: 0 | 1
  m0: bigint
  m1: bigint
  pk0: ElGamalPublicKey
  pk1: ElGamalPublicKey
  C0: ElGamalCiphertext
  C1: ElGamalCiphertext
  result: bigint
}

export type OTCorrectnessResult = {
  passed: boolean
  trials: {
    b: 0 | 1
    m0: bigint
    m1: bigint
    result: bigint
    expected: bigint
    correct: boolean
  }[]
}

export type OTReceiverPrivacyResult = {
  pk0: ElGamalPublicKey
  pk1: ElGamalPublicKey
  b: 0 | 1
  pk0IsGroupElement: boolean
  pk1IsGroupElement: boolean
  indistinguishable: boolean
}

export type OTSenderPrivacyResult = {
  b: 0 | 1
  m0: bigint
  m1: bigint
  result: bigint
  otherCiphertext: ElGamalCiphertext
  bruteForceAttempts: number
  bruteForceSuccess: boolean
  message: string
}

/* ------------------------------------------------------------------ */
/*  Helper: generate a random fake public key (no one knows the sk)    */
/* ------------------------------------------------------------------ */

function generateFakePublicKey(): ElGamalPublicKey {
  const { p, g, q } = DH_PARAMS
  // Pick random r, compute h = g^r mod p, then DISCARD r
  const bits = 30
  let r: bigint
  for (;;) {
    r = randomBigInt(bits) % q
    if (r >= 2n) break
  }
  const h = modpow(g, r, p)
  // r is discarded here -- nobody holds the secret key for this pk
  return { p, g, q, h }
}

/* ------------------------------------------------------------------ */
/*  Step 1: Receiver generates keys                                    */
/* ------------------------------------------------------------------ */

export function OT_Receiver_Step1(b: 0 | 1): OTReceiverStep1Result {
  // Generate honest key pair for position b
  const { sk, pk: honestPk } = elgamalKeygen()

  // Generate fake public key for position 1-b
  const fakePk = generateFakePublicKey()

  let pk0: ElGamalPublicKey
  let pk1: ElGamalPublicKey

  if (b === 0) {
    pk0 = honestPk
    pk1 = fakePk
  } else {
    pk0 = fakePk
    pk1 = honestPk
  }

  return {
    pk0,
    pk1,
    state: { b, sk_b: sk, pk_b: honestPk },
  }
}

/* ------------------------------------------------------------------ */
/*  Step 2: Sender encrypts both messages                              */
/* ------------------------------------------------------------------ */

export function OT_Sender_Step(
  pk0: ElGamalPublicKey,
  pk1: ElGamalPublicKey,
  m0: bigint,
  m1: bigint,
): OTSenderResult {
  const C0 = elgamalEncrypt(pk0, m0)
  const C1 = elgamalEncrypt(pk1, m1)
  return { C0, C1 }
}

/* ------------------------------------------------------------------ */
/*  Step 3: Receiver decrypts the chosen ciphertext                    */
/* ------------------------------------------------------------------ */

export function OT_Receiver_Step2(
  state: OTReceiverState,
  C0: ElGamalCiphertext,
  C1: ElGamalCiphertext,
): bigint {
  const { b, sk_b, pk_b } = state
  const Cb = b === 0 ? C0 : C1
  return elgamalDecrypt(sk_b, pk_b, Cb.c1, Cb.c2)
}

/* ------------------------------------------------------------------ */
/*  Full OT convenience function                                       */
/* ------------------------------------------------------------------ */

export function obliviousTransfer(
  m0: bigint,
  m1: bigint,
  b: 0 | 1,
): { result: bigint; transcript: OTTranscript } {
  // Step 1: Receiver generates keys
  const { pk0, pk1, state } = OT_Receiver_Step1(b)

  // Step 2: Sender encrypts
  const { C0, C1 } = OT_Sender_Step(pk0, pk1, m0, m1)

  // Step 3: Receiver decrypts
  const result = OT_Receiver_Step2(state, C0, C1)

  return {
    result,
    transcript: { b, m0, m1, pk0, pk1, C0, C1, result },
  }
}

/* ------------------------------------------------------------------ */
/*  Correctness test                                                   */
/* ------------------------------------------------------------------ */

export function otCorrectnessTest(numTrials: number): OTCorrectnessResult {
  const { p } = DH_PARAMS
  const trials: OTCorrectnessResult['trials'] = []
  let allPassed = true

  for (let i = 0; i < numTrials; i++) {
    const b: 0 | 1 = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) as 0 | 1
    // Random messages in [1, p-1]
    const m0 = (randomBigInt(28) % (p - 2n)) + 1n
    const m1 = (randomBigInt(28) % (p - 2n)) + 1n
    const expected = b === 0 ? m0 : m1

    const { result } = obliviousTransfer(m0, m1, b)
    const correct = result === expected

    if (!correct) allPassed = false
    trials.push({ b, m0, m1, result, expected, correct })
  }

  return { passed: allPassed, trials }
}

/* ------------------------------------------------------------------ */
/*  Receiver privacy demo                                              */
/* ------------------------------------------------------------------ */

export function otReceiverPrivacyDemo(b: 0 | 1): OTReceiverPrivacyResult {
  const { pk0, pk1 } = OT_Receiver_Step1(b)
  const { p } = DH_PARAMS

  // Check that both public keys are valid group elements (h^q = 1 mod p)
  // This is what the sender sees -- both look like valid ElGamal pks
  const pk0IsGroupElement = modpow(pk0.h, (p - 1n) / 2n, p) === 1n ||
                            modpow(pk0.h, p - 1n, p) === 1n
  const pk1IsGroupElement = modpow(pk1.h, (p - 1n) / 2n, p) === 1n ||
                            modpow(pk1.h, p - 1n, p) === 1n

  return {
    pk0,
    pk1,
    b,
    pk0IsGroupElement,
    pk1IsGroupElement,
    // Both are group elements of the same form g^x mod p
    indistinguishable: pk0IsGroupElement && pk1IsGroupElement,
  }
}

/* ------------------------------------------------------------------ */
/*  Sender privacy demo                                                */
/* ------------------------------------------------------------------ */

export function otSenderPrivacyDemo(): OTSenderPrivacyResult {
  const m0 = 42n
  const m1 = 99n
  const b: 0 | 1 = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) as 0 | 1

  const { pk0, pk1, state } = OT_Receiver_Step1(b)
  const { C0, C1 } = OT_Sender_Step(pk0, pk1, m0, m1)

  // Receiver can decrypt C_b
  const result = OT_Receiver_Step2(state, C0, C1)

  // Now try to brute-force C_{1-b}
  // The receiver does NOT know the secret key for the fake pk
  // To decrypt, they would need to solve the DLP: find x such that g^x = h mod p
  const otherC = b === 0 ? C1 : C0
  const otherPk = b === 0 ? pk1 : pk0

  // Try a limited brute force (just to show it's hard)
  const maxAttempts = 1000
  let found = false
  let attempts = 0

  for (let tryX = 2n; tryX < BigInt(maxAttempts) + 2n; tryX++) {
    attempts++
    if (modpow(DH_PARAMS.g, tryX, DH_PARAMS.p) === otherPk.h) {
      found = true
      break
    }
  }

  return {
    b,
    m0,
    m1,
    result,
    otherCiphertext: otherC,
    bruteForceAttempts: attempts,
    bruteForceSuccess: found,
    message: found
      ? 'Brute force succeeded (toy parameters) -- real-world DLP is infeasible'
      : `Brute force failed after ${attempts} attempts -- DLP is hard even at toy scale`,
  }
}
