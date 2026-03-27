import type { ByteArray, PrimitiveInstanceBuild, PrimitiveOracle, TraceStep } from '../types'
import { PrimitiveMeta, type FoundationKind, type PrimitiveKind } from '../domain'
import { bytesToHex } from '../utils/hex'

// Real crypto implementations
import { aesDaviesMeyerOwfEval, makeAesOwfOracle, makeDlpOwfOracle } from '../crypto/owf'
import { makeAesPRF } from '../crypto/prf'
import { dlpOwfEval } from '../crypto/dlp'

export type FoundationInstanceBuilder = (seedBytes: ByteArray) => PrimitiveInstanceBuild

export type FoundationAPI = {
  asOWF: FoundationInstanceBuilder
  asPRF: FoundationInstanceBuilder
  asPRP: FoundationInstanceBuilder
  asOWP?: FoundationInstanceBuilder
}

function implementedStep(
  functionApplied: string,
  inputBytes: ByteArray,
  outputBytes: ByteArray,
  note?: string
): TraceStep {
  return {
    id: `${functionApplied}:${bytesToHex(inputBytes).slice(0, 8)}`,
    functionApplied,
    inputHex: bytesToHex(inputBytes),
    outputHex: bytesToHex(outputBytes),
    status: { kind: 'implemented' },
    shortNote: note,
  }
}

function buildInstance(
  _kind: PrimitiveKind,
  oracle: PrimitiveOracle,
  trace: TraceStep[],
  material: ByteArray
): PrimitiveInstanceBuild {
  return { oracle, trace, material }
}

export function getFoundationAPI(foundationKind: FoundationKind): FoundationAPI {
  if (foundationKind === 'AES_128') {
    // ── AES-128 foundation ────────────────────────────────────────────────
    // AES-128 is a concrete PRP (and PRF via switching lemma).

    const asPRP: FoundationInstanceBuilder = (seedBytes) => {
      const key = new Uint8Array(16)
      key.set(seedBytes.slice(0, 16))
      const oracle = makeAesPRF(key)  // AES-128 as PRP/PRF
      const sample = oracle.evaluate(new Uint8Array(16))
      const trace: TraceStep[] = [
        implementedStep(
          'AES-128 PRP instantiation (key schedule)',
          key,
          sample,
          'AES_k(0¹²⁸) sampled'
        ),
      ]
      return buildInstance('PRP', oracle, trace, key)
    }

    const asPRF: FoundationInstanceBuilder = (seedBytes) => {
      const key = new Uint8Array(16)
      key.set(seedBytes.slice(0, 16))
      const oracle = makeAesPRF(key)
      const sample = oracle.evaluate(new Uint8Array(16))
      const trace: TraceStep[] = [
        implementedStep(
          'AES-128 PRP instantiation (key schedule)',
          key,
          sample,
          'AES_k(0¹²⁸) sampled'
        ),
        implementedStep(
          'PRP → PRF switching lemma (AES on superpolynomial domain)',
          key,
          sample,
          'AES is PRF: Adv_PRF ≤ Adv_PRP + q²/2ⁿ'
        ),
      ]
      return buildInstance('PRF', oracle, trace, key)
    }

    const asOWF: FoundationInstanceBuilder = (seedBytes) => {
      const key = new Uint8Array(16)
      key.set(seedBytes.slice(0, 16))
      const owfOut = aesDaviesMeyerOwfEval(key)
      const oracle = makeAesOwfOracle()
      const trace: TraceStep[] = [
        implementedStep(
          'AES Davies-Meyer OWF: f(k) = AES_k(0¹²⁸) ⊕ k',
          key,
          owfOut,
          'Compression OWF from AES PRP'
        ),
      ]
      return buildInstance('OWF', oracle, trace, owfOut)
    }

    return { asOWF, asPRF, asPRP }
  }

  // ── DLP foundation ────────────────────────────────────────────────────────
  // DLP is a concrete OWF/OWP: f(x) = g^x mod p

  const asOWF: FoundationInstanceBuilder = (seedBytes) => {
    const x = seedBytes.slice(0, 4)
    const owfOut = dlpOwfEval(x)
    const material = new Uint8Array(16)
    material.set(owfOut, 12)  // right-align 4-byte DLP output in 16 bytes
    const oracle = makeDlpOwfOracle()
    const trace: TraceStep[] = [
      implementedStep(
        'DLP OWF: f(x) = g^x mod p  (p=1,073,741,827, g=2)',
        x,
        owfOut,
        `g^${Array.from(x).map(b=>b.toString(16).padStart(2,'0')).join('')} mod p`
      ),
    ]
    return buildInstance('OWF', oracle, trace, material)
  }

  const asOWP: FoundationInstanceBuilder = (seedBytes) => {
    const owfBuild = asOWF(seedBytes)
    // DLP is already a OWP on Z_q (bijective on the group)
    const trace: TraceStep[] = [
      ...owfBuild.trace,
      implementedStep(
        'OWF → OWP (DLP is bijective on Z_q)',
        seedBytes.slice(0, 4),
        owfBuild.material ?? new Uint8Array(16),
        'DLP is a OWP on Z_q: f(x)=g^x mod p is a permutation'
      ),
    ]
    return { oracle: owfBuild.oracle, trace, material: owfBuild.material }
  }

  const fallbackMissing = (): PrimitiveInstanceBuild => {
    throw new Error('DLP foundation does not directly expose this primitive.')
  }

  return {
    asOWF,
    asPRF: fallbackMissing,
    asPRP: fallbackMissing,
    asOWP,
  }
}

export function instantiateFoundationStart(
  foundationKind: FoundationKind,
  seedBytes: ByteArray
): { startKind: PrimitiveKind; instance: PrimitiveInstanceBuild } {
  const api = getFoundationAPI(foundationKind)
  const startKind = foundationKind === 'AES_128' ? 'PRP' : 'OWF'
  const instance = startKind === 'PRP' ? api.asPRP(seedBytes) : api.asOWF(seedBytes)
  return { startKind, instance }
}

// Suppress unused import warning
void PrimitiveMeta
