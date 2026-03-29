/**
 * PA#19 — Secure AND, XOR, and NOT Gates
 *
 * Implements:
 * - Secure AND(a, b) via 1-out-of-2 Oblivious Transfer from PA#18
 * - Secure XOR(a, b) via additive secret sharing over Z_2 (free -- no OT)
 * - Secure NOT(a) via local bit flip (free -- no communication)
 * - Truth table verification across all 4 input combinations
 * - Privacy analysis showing OT hides inputs from both parties
 *
 * Uses obliviousTransfer from PA#18, which uses ElGamal from PA#16,
 * DH params from PA#11, and modpow/randomBigInt from PA#13.
 */

import {
  obliviousTransfer,
  type OTTranscript,
} from './obliviousTransfer'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type Bit = 0 | 1

export type SecureANDResult = {
  result: number
  aliceLearnedB: false
  bobLearnedA: false
  otTranscript: OTTranscript
}

export type SecureXORResult = {
  result: number
  shares: { alice: number; bob: number }
}

export type SecureNOTResult = {
  result: number
}

export type TruthTableEntry = {
  a: Bit
  b: Bit
  andResult: number
  andExpected: number
  andCorrect: boolean
  xorResult: number
  xorExpected: number
  xorCorrect: boolean
}

export type TruthTableResult = {
  passed: boolean
  entries: TruthTableEntry[]
}

export type PrivacyCheckResult = {
  a: Bit
  b: Bit
  andResult: number
  otTranscript: OTTranscript
  bobView: {
    choiceBit: Bit
    receivedValue: bigint
    canDetermineA: boolean
    explanation: string
  }
  aliceView: {
    sentMessages: { m0: bigint; m1: bigint }
    canDetermineB: boolean
    explanation: string
  }
}

/* ------------------------------------------------------------------ */
/*  Secure AND via OT                                                  */
/* ------------------------------------------------------------------ */

export function secureAND(a: Bit, b: Bit): SecureANDResult {
  // Alice (sender) sets OT messages: m0 = 0, m1 = a
  // Bob (receiver) uses choice bit b
  // Bob receives m_b: if b=0, gets 0; if b=1, gets a
  // So m_b = a AND b
  const m0 = 0n
  const m1 = BigInt(a)
  const { result, transcript } = obliviousTransfer(m0, m1, b)

  return {
    result: Number(result),
    aliceLearnedB: false,
    bobLearnedA: false,
    otTranscript: transcript,
  }
}

/* ------------------------------------------------------------------ */
/*  Secure XOR via additive secret sharing over Z_2                    */
/* ------------------------------------------------------------------ */

export function secureXOR(a: Bit, b: Bit): SecureXORResult {
  // Alice samples random r in {0,1}, sends r to Bob (simulated)
  const r = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) as Bit

  // Alice's share: a XOR r
  const aliceShare = a ^ r
  // Bob's share: b XOR r
  const bobShare = b ^ r

  // Output = aliceShare XOR bobShare = (a XOR r) XOR (b XOR r) = a XOR b
  const result = aliceShare ^ bobShare

  return {
    result,
    shares: { alice: aliceShare, bob: bobShare },
  }
}

/* ------------------------------------------------------------------ */
/*  Secure NOT (local, no communication)                               */
/* ------------------------------------------------------------------ */

export function secureNOT(a: Bit): SecureNOTResult {
  return { result: 1 - a }
}

/* ------------------------------------------------------------------ */
/*  Truth table verification                                           */
/* ------------------------------------------------------------------ */

export function truthTableTest(repetitions = 10): TruthTableResult {
  const combos: [Bit, Bit][] = [[0, 0], [0, 1], [1, 0], [1, 1]]
  const entries: TruthTableEntry[] = []
  let allPassed = true

  for (const [a, b] of combos) {
    const andExpected = a & b
    const xorExpected = a ^ b

    for (let trial = 0; trial < repetitions; trial++) {
      const andRes = secureAND(a, b)
      const xorRes = secureXOR(a, b)

      const andCorrect = andRes.result === andExpected
      const xorCorrect = xorRes.result === xorExpected

      if (!andCorrect || !xorCorrect) allPassed = false

      entries.push({
        a,
        b,
        andResult: andRes.result,
        andExpected,
        andCorrect,
        xorResult: xorRes.result,
        xorExpected,
        xorCorrect,
      })
    }
  }

  return { passed: allPassed, entries }
}

/* ------------------------------------------------------------------ */
/*  Privacy verification                                               */
/* ------------------------------------------------------------------ */

export function privacyCheck(a: Bit, b: Bit): PrivacyCheckResult {
  const andRes = secureAND(a, b)
  const { otTranscript } = andRes

  // Bob's view: he knows b and learns m_b = a AND b
  // If b=0, Bob always gets 0 regardless of a -> cannot determine a
  // If b=1, Bob gets a -> but this IS a AND b, which is the output.
  // In a secure computation, both parties learn the output.
  // Bob cannot learn a beyond what the output reveals.
  const bobCanDetermineA = false
  const bobExplanation = b === 0
    ? 'Bob chose b=0 and received 0. This happens regardless of a (0 AND 0 = 0, 1 AND 0 = 0). Bob learns nothing about a.'
    : 'Bob chose b=1 and received a AND 1 = a. But this IS the output a AND b = a. Both parties are allowed to learn the output. Bob cannot learn a beyond what the output reveals.'

  // Alice's view: she set m0=0, m1=a, sent ciphertexts to Bob
  // OT receiver privacy guarantees Alice cannot determine b
  // Both pk0 and pk1 look like valid ElGamal public keys
  const aliceCanDetermineB = false
  const aliceExplanation =
    'Alice sent (C0, C1) encrypting (0, a) under (pk0, pk1). ' +
    'Both public keys are indistinguishable group elements (DDH assumption). ' +
    'Alice cannot determine which key Bob holds the secret for, so she cannot learn b.'

  return {
    a,
    b,
    andResult: andRes.result,
    otTranscript,
    bobView: {
      choiceBit: b,
      receivedValue: otTranscript.result,
      canDetermineA: bobCanDetermineA,
      explanation: bobExplanation,
    },
    aliceView: {
      sentMessages: { m0: 0n, m1: BigInt(a) },
      canDetermineB: aliceCanDetermineB,
      explanation: aliceExplanation,
    },
  }
}
