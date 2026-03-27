import type {
  ByteArray,
  CliqueRouteStep,
  PrimitiveInstanceBuild,
  PrimitiveOracle,
  ReductionMode,
  StepStatus,
  TraceStep,
} from '../types'
import type { FoundationKind, PrimitiveKind } from '../domain'
import { PrimitiveMeta } from '../domain'
import { bytesToHex, parseFlexibleInputToBytes } from '../utils/hex'
import { makeToyOracle, makeToyReductionInput } from '../toy'
import { reduce as reduceClique, type ReductionResult } from '../reductions/routing'

// Real crypto
import { makePRGOracle } from '../crypto/prg'
import { makeGgmPRF, makePRGFromPRF } from '../crypto/prf'

const IMPLEMENTED: StepStatus = { kind: 'implemented' }

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

/**
 * Build the next oracle in the reduction chain.
 * For PA1/PA2 edges: wraps the current oracle with real construction.
 * For higher PA edges: falls back to toy oracle from output bytes.
 */
function buildNextOracle(
  edge: CliqueRouteStep,
  currentOracle: PrimitiveOracle,
  queryBytes: ByteArray
): { oracle: PrimitiveOracle; traceInput: ByteArray; traceOutput: ByteArray; status: StepStatus; note: string } {
  switch (edge.theorem) {
    case 'HILL hard-core-bit construction': {
      // OWF → PRG: wrap OWF oracle in HILL PRG construction
      const prgOracle = makePRGOracle(currentOracle)
      const out = prgOracle.evaluate(queryBytes)
      return {
        oracle: prgOracle,
        traceInput: queryBytes,
        traceOutput: out,
        status: IMPLEMENTED,
        note: 'G(seed) = b(f⁰(seed))‖b(f¹(seed))‖… (HILL, hard-core bit = LSB of OWF output)',
      }
    }

    case 'GGM tree construction': {
      // PRG → PRF: wrap PRG oracle in GGM tree keyed by query
      const key = queryBytes.length >= 16 ? queryBytes.slice(0, 16) : (() => {
        const k = new Uint8Array(16); k.set(queryBytes); return k
      })()
      const prfOracle = makeGgmPRF(currentOracle, key)
      const out = prfOracle.evaluate(queryBytes)
      return {
        oracle: prfOracle,
        traceInput: queryBytes,
        traceOutput: out,
        status: IMPLEMENTED,
        note: 'GGM: Fₖ(x) = G_{xₙ}(…G_{x₁}(k)…) — root-to-leaf traversal',
      }
    }

    case 'Define G(s)=Fs(0^n)||Fs(1^n)': {
      // PRF → PRG backward: build PRG from PRF
      const prgOracle = makePRGFromPRF(currentOracle)
      const out = prgOracle.evaluate(queryBytes)
      return {
        oracle: prgOracle,
        traceInput: queryBytes,
        traceOutput: out,
        status: IMPLEMENTED,
        note: 'G(s) = Fₛ(0ⁿ)‖Fₛ(1ⁿ) — PRF gives length-doubling PRG',
      }
    }

    case 'Any PRG is immediately a OWF': {
      // PRG → OWF backward: trivial (query the PRG directly)
      const out = currentOracle.evaluate(queryBytes)
      return {
        oracle: { evaluate: (x) => currentOracle.evaluate(x) },
        traceInput: queryBytes,
        traceOutput: out,
        status: IMPLEMENTED,
        note: 'f(s) = G(s) is OWF: inversion of f implies distinguisher for G',
      }
    }

    case 'PRP indistinguishable from PRF (switching lemma)': {
      // PRP → PRF backward: same oracle (AES is both)
      const out = currentOracle.evaluate(queryBytes)
      return {
        oracle: currentOracle,
        traceInput: queryBytes,
        traceOutput: out,
        status: IMPLEMENTED,
        note: 'AES is statistically close to PRF: Adv_PRF ≤ Adv_PRP + q²/2ⁿ',
      }
    }

    case 'Mack(m) = Fk(m)': {
      // PRF → MAC forward: Mac_k(m) = F_k(m)
      const out = currentOracle.evaluate(queryBytes)
      return {
        oracle: currentOracle,
        traceInput: queryBytes,
        traceOutput: out,
        status: { kind: 'not_implemented', duePa: 5 },
        note: 'Not implemented yet (due: PA#5)',
      }
    }

    default: {
      // Toy fallback for unimplemented edges
      const paramInput = makeToyReductionInput(queryBytes, edge.reductionInputSalt)
      const outBytes = currentOracle.evaluate(paramInput)
      return {
        oracle: makeToyOracle(edge.toKind as PrimitiveKind, outBytes),
        traceInput: paramInput,
        traceOutput: outBytes,
        status: { kind: 'not_implemented', duePa: edge.duePa },
        note: `Not implemented yet (due: PA#${edge.duePa})`,
      }
    }
  }
}

export function reduceLeg2(args: {
  source: { oracle: PrimitiveInstanceBuild['oracle']; kind: PrimitiveKind }
  targetKind: PrimitiveKind
  query: string
  mode: ReductionMode
  foundationKind: FoundationKind
}): { ok: true; plan: CliqueRouteStep[]; trace: TraceStep[]; output: ByteArray } | { ok: false; error: string; suggestion?: string } {
  const queryBytes = parseFlexibleInputToBytes(args.query)

  const route: ReductionResult = reduceClique(
    args.source.kind,
    args.targetKind,
    args.foundationKind,
    args.mode
  )

  if (!route.ok) {
    return { ok: false, error: route.error, suggestion: route.suggestion }
  }

  let oracle = args.source.oracle
  const trace: TraceStep[] = []

  for (const edge of route.steps) {
    const { oracle: nextOracle, traceInput, traceOutput, status, note } = buildNextOracle(
      edge,
      oracle,
      queryBytes
    )
    trace.push(makeTraceStep(edge.theorem, traceInput, traceOutput, status, note))
    oracle = nextOracle
  }

  const finalOut = oracle.evaluate(queryBytes)
  const finalStatus: StepStatus =
    ['OWF', 'PRG', 'PRF', 'PRP'].includes(args.targetKind)
      ? IMPLEMENTED
      : { kind: 'not_implemented', duePa: PrimitiveMeta[args.targetKind].duePa }

  trace.push(
    makeTraceStep(
      `${args.targetKind} evaluation (black-box oracle query)`,
      queryBytes,
      finalOut,
      finalStatus,
      finalStatus.kind === 'implemented' ? `F(query) computed` : undefined
    )
  )

  return { ok: true, trace, output: finalOut, plan: route.steps }
}
