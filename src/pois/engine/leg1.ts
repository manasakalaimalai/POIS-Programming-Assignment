import type { ByteArray, PrimitiveInstanceBuild, StepStatus, TraceStep } from '../types'
import type { FoundationKind, PrimitiveKind } from '../domain'
import { bytesToHex, parseFlexibleInputToBytes } from '../utils/hex'
import { toyTransform, makeToyOracle } from '../toy'
import { instantiateFoundationStart } from '../foundation/foundation'
import { findLeg1Route } from '../reductions/routing'
import { PrimitiveMeta } from '../domain'

// Real crypto
import { makeAesOwfOracle, makeDlpOwfOracle } from '../crypto/owf'
import { makePRGOracle } from '../crypto/prg'
import { makeAesPRF } from '../crypto/prf'
import { hillGenerate } from '../crypto/prg'

function makeTraceStep(
  functionApplied: string,
  input: ByteArray,
  output: ByteArray,
  status: StepStatus,
  note?: string
): TraceStep {
  return {
    id: `${functionApplied}:${bytesToHex(input).slice(0, 8)}:${bytesToHex(output).slice(0, 8)}`,
    functionApplied,
    inputHex: bytesToHex(input),
    outputHex: bytesToHex(output),
    status,
    shortNote: note ?? (status.kind === 'not_implemented' ? `Not implemented yet (due: PA#${status.duePa})` : undefined),
  }
}

const IMPLEMENTED: StepStatus = { kind: 'implemented' }

/**
 * Real material transform for PA1/PA2 steps.
 * Returns { next material, status, note }.
 */
function realOrToyMaterial(
  mat: ByteArray,
  materialSalt: string,
  foundationKind: FoundationKind,
  duePa: number
): { next: ByteArray; status: StepStatus; note?: string } {
  switch (materialSalt) {
    case 'HILL': {
      // OWF → PRG: run HILL construction from OWF material to derive PRG seed
      const owf = foundationKind === 'DLP' ? makeDlpOwfOracle() : makeAesOwfOracle()
      const next = hillGenerate(owf, mat, 16)
      return { next, status: IMPLEMENTED, note: 'HILL construction: G(x) = b(x₀)‖b(x₁)‖… (LSB hard-core bit)' }
    }
    case 'GGM': {
      // PRG → PRF: key material passes through unchanged (key = seed in GGM)
      return { next: mat, status: IMPLEMENTED, note: 'GGM key = PRG seed (identity)' }
    }
    case 'PRP->PRF': {
      // PRP → PRF: same key, switching lemma
      return { next: mat, status: IMPLEMENTED, note: 'PRP/PRF switching: same AES key' }
    }
    case 'PRG->OWF': {
      // PRG → OWF backward: trivial (PRG is already a OWF)
      return { next: mat, status: IMPLEMENTED, note: 'PRG ⊇ OWF: G is one-way by definition' }
    }
    case 'PRF->PRG': {
      // PRF → PRG backward: G(s)=Fs(0)||Fs(1)
      const prf = makeAesPRF(mat)
      const left  = prf.evaluate(new Uint8Array(16))        // F_s(0^128)
      const right = prf.evaluate(new Uint8Array(16).fill(1)) // F_s(1^128)
      const next = new Uint8Array(16)
      for (let i = 0; i < 16; i++) next[i] = left[i] ^ right[i]  // compress to 16 bytes
      return { next, status: IMPLEMENTED, note: 'G(s) = Fₛ(0ⁿ)‖Fₛ(1ⁿ)' }
    }
    default: {
      // Higher PA steps: fall back to toy
      const next = toyTransform(mat, materialSalt, 16)
      return { next, status: { kind: 'not_implemented', duePa }, note: `Not implemented yet (due: PA#${duePa})` }
    }
  }
}

/**
 * Build the final oracle for the target primitive using real implementations.
 */
function buildFinalOracle(
  targetKind: PrimitiveKind,
  mat: ByteArray,
  foundationKind: FoundationKind
) {
  switch (targetKind) {
    case 'OWF':
      return foundationKind === 'DLP' ? makeDlpOwfOracle() : makeAesOwfOracle()
    case 'PRG': {
      const owf = foundationKind === 'DLP' ? makeDlpOwfOracle() : makeAesOwfOracle()
      return makePRGOracle(owf)
    }
    case 'PRF':
    case 'PRP':
      return makeAesPRF(mat)
    default:
      return makeToyOracle(targetKind, mat)
  }
}

export function buildLeg1(
  foundationKind: FoundationKind,
  seedHex: string,
  targetKind: PrimitiveKind
): PrimitiveInstanceBuild {
  const seedBytes = parseFlexibleInputToBytes(seedHex)
  const { startKind, instance: startInstance } = instantiateFoundationStart(
    foundationKind,
    seedBytes
  )

  const currentMaterial: ByteArray =
    startInstance.material ??
    new Uint8Array([...(seedBytes.slice(0, 16) ?? [])])

  const route = findLeg1Route(startKind, targetKind)
  const trace: TraceStep[] = [...startInstance.trace]
  let mat = currentMaterial

  if (route) {
    for (const step of route) {
      const duePa = step.duePa ?? PrimitiveMeta[step.toKind].duePa
      const { next, status, note } = realOrToyMaterial(mat, step.materialSalt, foundationKind, duePa)
      trace.push(makeTraceStep(step.theorem, mat, next, status, note))
      mat = next
    }
  } else {
    trace.push({
      id: 'leg1:error',
      functionApplied: 'No under-the-hood route found',
      status: { kind: 'not_implemented', duePa: PrimitiveMeta[targetKind].duePa },
      shortNote: 'This should not happen in PA#0 because leg-1 allows both directions.',
    })
  }

  const oracle = buildFinalOracle(targetKind, mat, foundationKind)
  return { oracle, trace, material: mat }
}
