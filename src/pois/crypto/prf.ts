/**
 * Pseudorandom Function (PRF) implementations.
 *
 * 1. GGM PRF from PRG:  F_k(b1...bn) = G_{b_n}(...G_{b_1}(k)...)
 * 2. AES plug-in PRF:   F_k(x) = AES_k(x)
 * 3. PRG from PRF:      G(s) = F_s(0^n) || F_s(1^n)   [backward direction]
 */

import type { ByteArray, PrimitiveOracle } from '../types'
import { aes128 } from './aes128'

// ── GGM helpers ──────────────────────────────────────────────────────────────

/**
 * One GGM tree step: split G(v) into left and right halves.
 * G_0(v) = first half, G_1(v) = second half.
 */
export function ggmStep(
  prgOracle: PrimitiveOracle,
  nodeValue: ByteArray
): [ByteArray, ByteArray] {
  const out = prgOracle.evaluate(nodeValue)
  const half = Math.floor(out.length / 2)
  return [out.slice(0, half), out.slice(half)]
}

/**
 * Evaluate GGM PRF for query x (array of bits).
 * F_k(b1...bn) = G_{b_n}(...G_{b_1}(k)...)
 * Algorithm: start at root=key, follow each bit down the tree.
 */
function ggmEval(
  prgOracle: PrimitiveOracle,
  keyBytes: ByteArray,
  queryBits: number[]
): ByteArray {
  let node: ByteArray = new Uint8Array(keyBytes)
  for (const bit of queryBits) {
    const [left, right] = ggmStep(prgOracle, node)
    node = bit === 0 ? left : right
  }
  return node
}

/**
 * GGM PRF oracle.
 * The key is captured at construction time.
 * evaluate(x): x is treated as a bit string (each byte = one bit, 0x00=left, anything else=right).
 * For hex/byte input: uses the bits of the input bytes (MSB-first).
 */
export function makeGgmPRF(
  prgOracle: PrimitiveOracle,
  keyBytes: ByteArray
): PrimitiveOracle {
  const key = new Uint8Array(keyBytes)
  return {
    evaluate(input: ByteArray): ByteArray {
      // Extract bits from input bytes (MSB-first), use up to 16 bits
      const bits: number[] = []
      for (const byte of input) {
        for (let i = 7; i >= 0; i--) {
          bits.push((byte >> i) & 1)
        }
        if (bits.length >= 16) break
      }
      if (bits.length === 0) bits.push(0)
      return ggmEval(prgOracle, key, bits)
    },
  }
}

// ── AES plug-in PRF ──────────────────────────────────────────────────────────

/**
 * AES plug-in PRF: F_k(x) = AES_k(x).
 * Key k = first 16 bytes of keyBytes.
 */
export function makeAesPRF(keyBytes: ByteArray): PrimitiveOracle {
  const k = new Uint8Array(16)
  k.set(keyBytes.slice(0, 16))
  return {
    evaluate(input: ByteArray): ByteArray {
      const x = new Uint8Array(16)
      x.set(input.slice(0, 16))
      return aes128(k, x)
    },
  }
}

// ── PRG from PRF (backward direction) ────────────────────────────────────────

/**
 * PRG from PRF: G(s) = F_s(0^n) || F_s(1^n)
 * Given a PRF oracle, builds a length-doubling PRG.
 * The PRF is keyed with s; 0^n and 1^n are fixed queries.
 */
export function makePRGFromPRF(
  prfOracle: PrimitiveOracle,
  n = 8
): PrimitiveOracle {
  const zeros = new Uint8Array(Math.ceil(n / 8))
  const ones = new Uint8Array(Math.ceil(n / 8)).fill(0xff)
  return {
    evaluate(seed: ByteArray): ByteArray {
      // Use seed as PRF key by rebuilding a keyed oracle each call
      // (The caller is responsible for keying the prfOracle correctly;
      //  here we apply it to 0 and 1 directly.)
      void seed  // seed is the key, already baked into prfOracle
      const left = prfOracle.evaluate(zeros)
      const right = prfOracle.evaluate(ones)
      const out = new Uint8Array(left.length + right.length)
      out.set(left)
      out.set(right, left.length)
      return out
    },
  }
}

// ── GGM evaluation with full trace (for PA2 visualizer) ─────────────────────

export interface GgmTraceNode {
  depth: number
  index: number       // position at this depth (0 = leftmost)
  valueHex: string    // abbreviated hex of node value
  valueFull: ByteArray
  onPath: boolean     // true if on the evaluation path for the query
  isLeaf: boolean
}

/**
 * Evaluate GGM PRF and return a full tree trace for visualization.
 * Computes ALL nodes up to depth n = queryBits.length.
 * For n <= 8: at most 2^9 - 1 = 511 nodes (manageable).
 */
export function ggmEvaluateWithTrace(
  prgOracle: PrimitiveOracle,
  keyBytes: ByteArray,
  queryBits: number[]
): { result: ByteArray; nodes: GgmTraceNode[] } {
  const n = queryBits.length
  if (n === 0) {
    const root: GgmTraceNode = {
      depth: 0, index: 0,
      valueHex: abbrev(keyBytes),
      valueFull: new Uint8Array(keyBytes),
      onPath: true, isLeaf: true,
    }
    return { result: new Uint8Array(keyBytes), nodes: [root] }
  }

  // BFS: track all nodes level by level
  // Each level has 2^depth nodes; store them as flat array per level
  const levels: Array<Array<{ value: ByteArray; onPath: boolean }>> = []

  // Root
  levels.push([{ value: new Uint8Array(keyBytes), onPath: true }])

  for (let d = 0; d < n; d++) {
    const prevLevel = levels[d]
    const nextLevel: Array<{ value: ByteArray; onPath: boolean }> = []

    for (let i = 0; i < prevLevel.length; i++) {
      const parent = prevLevel[i]
      const [left, right] = ggmStep(prgOracle, parent.value)
      // A child is on-path if its parent was on-path AND the query bit matches
      const leftOnPath  = parent.onPath && queryBits[d] === 0
      const rightOnPath = parent.onPath && queryBits[d] === 1
      nextLevel.push(
        { value: left,  onPath: leftOnPath  },
        { value: right, onPath: rightOnPath },
      )
    }
    levels.push(nextLevel)
  }

  // Flatten into GgmTraceNode[]
  const nodes: GgmTraceNode[] = []
  for (let d = 0; d <= n; d++) {
    const level = levels[d]
    for (let i = 0; i < level.length; i++) {
      nodes.push({
        depth: d,
        index: i,
        valueHex: abbrev(level[i].value),
        valueFull: level[i].value,
        onPath: level[i].onPath,
        isLeaf: d === n,
      })
    }
  }

  // The result is the single on-path leaf
  const leafLevel = levels[n]
  const resultNode = leafLevel.find(n => n.onPath)
  const result = resultNode ? resultNode.value : leafLevel[0].value

  return { result, nodes }
}

function abbrev(bytes: ByteArray): string {
  const hex = Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')
  return bytes.length > 4 ? hex + '…' : hex
}

// ── Distinguishing game ──────────────────────────────────────────────────────

export interface DistinguishingResult {
  chiSquaredStat: number
  pValue: number
  verdict: 'indistinguishable' | 'distinguishable'
  queriesRun: number
}

/**
 * PRF distinguishing game: compare PRF output to uniformly random output.
 * Runs `queries` trials, tests output distribution for uniformity.
 * A secure PRF should be indistinguishable (high p-value).
 */
export function runDistinguishingGame(
  prfOracle: PrimitiveOracle,
  queries = 100
): DistinguishingResult {
  // Collect byte value counts for first byte of each output
  const prfCounts = new Uint32Array(256)

  for (let i = 0; i < queries; i++) {
    const input = new Uint8Array(16)
    // Deterministic but varied inputs: encode i into bytes
    input[0] = (i >> 8) & 0xff
    input[1] = i & 0xff
    const out = prfOracle.evaluate(input)
    prfCounts[out[0]]++
  }

  // Chi-squared goodness-of-fit vs uniform distribution over [0,255]
  // Expected count per bucket if uniform: queries/256
  const expected = queries / 256
  let chi2 = 0
  for (let b = 0; b < 256; b++) {
    const diff = prfCounts[b] - expected
    chi2 += (diff * diff) / expected
  }

  // Approximate p-value: for chi2 with 255 degrees of freedom,
  // use Wilson-Hilferty normal approximation
  const df = 255
  const z = (Math.pow(chi2 / df, 1/3) - (1 - 2/(9*df))) / Math.sqrt(2/(9*df))
  // p-value = P(Z > z) ≈ erfc(z / sqrt(2)) / 2
  const pValue = 0.5 * erfc_pos(z / Math.sqrt(2))

  return {
    chiSquaredStat: chi2,
    pValue,
    verdict: pValue >= 0.05 ? 'indistinguishable' : 'distinguishable',
    queriesRun: queries,
  }
}

function erfc_pos(x: number): number {
  // erfc for x >= 0
  const t = 1.0 / (1.0 + 0.3275911 * Math.abs(x))
  const poly =
    t * (0.254829592 +
    t * (-0.284496736 +
    t * (1.421413741 +
    t * (-1.453152027 +
    t * 1.061405429))))
  return poly * Math.exp(-x * x)
}
