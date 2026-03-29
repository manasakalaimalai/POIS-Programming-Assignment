/**
 * PA#20 — All 2-Party Secure Computation (Yao/GMW style)
 *
 * Boolean circuit evaluator using PA#19 secure gates (AND via OT, XOR/NOT free).
 * Three mandatory circuits:
 *   1. Millionaire's Problem (greater-than comparison)
 *   2. Secure Equality
 *   3. Secure Addition (mod 2^n)
 *
 * Lineage: PA#20 -> PA#19 AND -> PA#18 OT -> PA#16 ElGamal -> PA#13 Miller-Rabin
 */

import {
  secureAND,
  secureXOR,
  secureNOT,
  type Bit,
} from './secureGates'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type GateType = 'AND' | 'XOR' | 'NOT' | 'INPUT'

export type Gate = {
  id: number
  type: GateType
  inputs: number[]      // gate IDs of inputs
  owner?: 'alice' | 'bob'  // for INPUT gates
  inputIndex?: number       // which bit of the owner's input
}

export type Circuit = {
  gates: Gate[]
  outputGateIds: number[]
  numAliceInputs: number
  numBobInputs: number
}

export type GateLogEntry = {
  gateId: number
  type: GateType
  output: number
}

export type EvalResult = {
  outputs: number[]
  otCalls: number
  timeMs: number
  gateLog: GateLogEntry[]
}

export type PerfRow = {
  circuit: string
  n4OtCalls: number
  n4TimeMs: number
  n8OtCalls: number
  n8TimeMs: number
}

/* ------------------------------------------------------------------ */
/*  Gate ID counter                                                    */
/* ------------------------------------------------------------------ */

let _nextGateId = 0

export function resetGateIds(): void {
  _nextGateId = 0
}

/* ------------------------------------------------------------------ */
/*  Circuit builder helpers                                            */
/* ------------------------------------------------------------------ */

export function inputGate(owner: 'alice' | 'bob', index: number): Gate {
  return { id: _nextGateId++, type: 'INPUT', inputs: [], owner, inputIndex: index }
}

export function andGate(a: number, b: number): Gate {
  return { id: _nextGateId++, type: 'AND', inputs: [a, b] }
}

export function xorGate(a: number, b: number): Gate {
  return { id: _nextGateId++, type: 'XOR', inputs: [a, b] }
}

export function notGate(a: number): Gate {
  return { id: _nextGateId++, type: 'NOT', inputs: [a] }
}

/* ------------------------------------------------------------------ */
/*  Bit <-> number helpers                                             */
/* ------------------------------------------------------------------ */

/** Convert number to n-bit array (LSB first: index 0 = least significant bit) */
export function numberToBits(x: number, n: number): number[] {
  const bits: number[] = []
  for (let i = 0; i < n; i++) {
    bits.push((x >> i) & 1)
  }
  return bits
}

/** Convert bit array (LSB first) to number */
export function bitsToNumber(bits: number[]): number {
  let v = 0
  for (let i = 0; i < bits.length; i++) {
    v |= (bits[i] & 1) << i
  }
  return v
}

/* ------------------------------------------------------------------ */
/*  Secure circuit evaluation                                          */
/* ------------------------------------------------------------------ */

export function secureEval(
  circuit: Circuit,
  aliceInputs: number[],
  bobInputs: number[],
): EvalResult {
  const t0 = performance.now()
  const wire: Map<number, number> = new Map()
  let otCalls = 0
  const gateLog: GateLogEntry[] = []

  // Topological sort: since gates are built in order with increasing IDs,
  // and each gate only references lower-ID gates, we can just iterate in order.
  const sorted = [...circuit.gates].sort((a, b) => a.id - b.id)

  for (const gate of sorted) {
    let output: number

    switch (gate.type) {
      case 'INPUT': {
        if (gate.owner === 'alice') {
          output = aliceInputs[gate.inputIndex!] & 1
        } else {
          output = bobInputs[gate.inputIndex!] & 1
        }
        break
      }
      case 'AND': {
        const a = wire.get(gate.inputs[0])!
        const b = wire.get(gate.inputs[1])!
        const res = secureAND(a as Bit, b as Bit)
        output = res.result
        otCalls++
        break
      }
      case 'XOR': {
        const a = wire.get(gate.inputs[0])!
        const b = wire.get(gate.inputs[1])!
        const res = secureXOR(a as Bit, b as Bit)
        output = res.result
        break
      }
      case 'NOT': {
        const a = wire.get(gate.inputs[0])!
        const res = secureNOT(a as Bit)
        output = res.result
        break
      }
      default:
        throw new Error(`Unknown gate type: ${gate.type}`)
    }

    wire.set(gate.id, output)
    gateLog.push({ gateId: gate.id, type: gate.type, output })
  }

  const outputs = circuit.outputGateIds.map(id => wire.get(id)!)
  const timeMs = performance.now() - t0

  return { outputs, otCalls, timeMs, gateLog }
}

/* ------------------------------------------------------------------ */
/*  Circuit 1: Greater-Than (Millionaire's Problem)                    */
/* ------------------------------------------------------------------ */

/**
 * Builds a ripple comparator: x > y for n-bit integers.
 * Processes from MSB to LSB. Outputs a single bit (1 if x > y).
 *
 * At each bit position i (from MSB down):
 *   xi_gt_yi = xi AND NOT(yi)        -- x wins this bit
 *   yi_gt_xi = yi AND NOT(xi)        -- y wins this bit
 *   same_i   = NOT(xi XOR yi)        -- bits are equal
 *
 * Running result:
 *   gt = gt_prev OR (same_so_far AND xi_gt_yi)
 *
 * But OR(a,b) = NOT(AND(NOT(a), NOT(b)))
 *
 * We track "all bits so far are equal" and "x > y so far".
 */
export function buildGreaterThanCircuit(n: number): Circuit {
  resetGateIds()
  const gates: Gate[] = []
  const add = (g: Gate) => { gates.push(g); return g.id }

  // Alice inputs: bits of x (index 0 = LSB)
  const ax: number[] = []
  for (let i = 0; i < n; i++) ax.push(add(inputGate('alice', i)))

  // Bob inputs: bits of y (index 0 = LSB)
  const bx: number[] = []
  for (let i = 0; i < n; i++) bx.push(add(inputGate('bob', i)))

  // Process from MSB (index n-1) down to LSB (index 0)
  // gtSoFar: x > y considering bits processed so far
  // eqSoFar: all bits processed so far are equal
  let gtSoFar = -1
  let eqSoFar = -1

  for (let i = n - 1; i >= 0; i--) {
    const xi = ax[i]
    const yi = bx[i]

    // xi_gt_yi = xi AND NOT(yi)
    const notYi = add(notGate(yi))
    const xiGtYi = add(andGate(xi, notYi))

    // same_i = NOT(xi XOR yi)
    const xorBit = add(xorGate(xi, yi))
    const sameI = add(notGate(xorBit))

    if (gtSoFar === -1) {
      // First bit (MSB)
      gtSoFar = xiGtYi
      eqSoFar = sameI
    } else {
      // newGtContrib = eqSoFar AND xiGtYi
      const contrib = add(andGate(eqSoFar, xiGtYi))

      // gtSoFar = OR(gtSoFar, contrib) = NOT(AND(NOT(gtSoFar), NOT(contrib)))
      const notGt = add(notGate(gtSoFar))
      const notContrib = add(notGate(contrib))
      const andNots = add(andGate(notGt, notContrib))
      gtSoFar = add(notGate(andNots))

      // eqSoFar = eqSoFar AND sameI
      eqSoFar = add(andGate(eqSoFar, sameI))
    }
  }

  return {
    gates,
    outputGateIds: [gtSoFar],
    numAliceInputs: n,
    numBobInputs: n,
  }
}

/* ------------------------------------------------------------------ */
/*  Circuit 2: Equality                                                */
/* ------------------------------------------------------------------ */

/**
 * Secure Equality: x = y
 * XOR each pair of bits. OR all XOR results. Negate.
 * eq = NOT( XOR(x0,y0) OR XOR(x1,y1) OR ... )
 * OR(a,b) = NOT(AND(NOT(a), NOT(b)))
 */
export function buildEqualityCircuit(n: number): Circuit {
  resetGateIds()
  const gates: Gate[] = []
  const add = (g: Gate) => { gates.push(g); return g.id }

  const ax: number[] = []
  for (let i = 0; i < n; i++) ax.push(add(inputGate('alice', i)))
  const bx: number[] = []
  for (let i = 0; i < n; i++) bx.push(add(inputGate('bob', i)))

  // XOR each pair
  const xors: number[] = []
  for (let i = 0; i < n; i++) {
    xors.push(add(xorGate(ax[i], bx[i])))
  }

  // OR-tree of all XOR results
  let orAcc = xors[0]
  for (let i = 1; i < n; i++) {
    // OR(orAcc, xors[i]) = NOT(AND(NOT(orAcc), NOT(xors[i])))
    const notA = add(notGate(orAcc))
    const notB = add(notGate(xors[i]))
    const a = add(andGate(notA, notB))
    orAcc = add(notGate(a))
  }

  // eq = NOT(orAcc)
  const eq = add(notGate(orAcc))

  return {
    gates,
    outputGateIds: [eq],
    numAliceInputs: n,
    numBobInputs: n,
  }
}

/* ------------------------------------------------------------------ */
/*  Circuit 3: Addition (mod 2^n)                                      */
/* ------------------------------------------------------------------ */

/**
 * Ripple-carry adder.
 * sum_i = x_i XOR y_i XOR carry_i
 * carry_{i+1} = (x_i AND y_i) XOR (carry_i AND (x_i XOR y_i))
 */
export function buildAdditionCircuit(n: number): Circuit {
  resetGateIds()
  const gates: Gate[] = []
  const add = (g: Gate) => { gates.push(g); return g.id }

  const ax: number[] = []
  for (let i = 0; i < n; i++) ax.push(add(inputGate('alice', i)))
  const bx: number[] = []
  for (let i = 0; i < n; i++) bx.push(add(inputGate('bob', i)))

  let carry = -1  // no carry for first bit
  const sumBits: number[] = []

  for (let i = 0; i < n; i++) {
    const xi = ax[i]
    const yi = bx[i]
    const xyXor = add(xorGate(xi, yi))

    let sumI: number
    if (carry === -1) {
      // First bit: sum = xi XOR yi, carry = xi AND yi
      sumI = xyXor
      carry = add(andGate(xi, yi))
    } else {
      // sum_i = (xi XOR yi) XOR carry
      sumI = add(xorGate(xyXor, carry))
      // carry_{i+1} = (xi AND yi) XOR (carry AND (xi XOR yi))
      const xyAnd = add(andGate(xi, yi))
      const cAndXor = add(andGate(carry, xyXor))
      carry = add(xorGate(xyAnd, cAndXor))
    }
    sumBits.push(sumI)
  }

  return {
    gates,
    outputGateIds: sumBits,  // LSB first
    numAliceInputs: n,
    numBobInputs: n,
  }
}

/* ------------------------------------------------------------------ */
/*  Performance report                                                 */
/* ------------------------------------------------------------------ */

export function runPerfReport(): PerfRow[] {
  const circuits: { name: string; build: (n: number) => Circuit }[] = [
    { name: 'Greater-Than', build: buildGreaterThanCircuit },
    { name: 'Equality',     build: buildEqualityCircuit },
    { name: 'Addition',     build: buildAdditionCircuit },
  ]

  const rows: PerfRow[] = []

  for (const { name, build } of circuits) {
    const c4 = build(4)
    const r4 = secureEval(c4, numberToBits(7, 4), numberToBits(3, 4))

    const c8 = build(8)
    const r8 = secureEval(c8, numberToBits(200, 8), numberToBits(100, 8))

    rows.push({
      circuit: name,
      n4OtCalls: r4.otCalls,
      n4TimeMs: r4.timeMs,
      n8OtCalls: r8.otCalls,
      n8TimeMs: r8.timeMs,
    })
  }

  return rows
}
