/**
 * PA#20 — 2-Party Secure Computation Demo
 *
 * Circuit selector tabs: Millionaire's Problem / Equality / Addition
 * Two panels (Alice | Bob) with input sliders
 * Secure evaluation with gate trace, OT count, and timing
 * Performance report table
 */

import { useState } from 'react'
import {
  buildGreaterThanCircuit,
  buildEqualityCircuit,
  buildAdditionCircuit,
  secureEval,
  numberToBits,
  bitsToNumber,
  runPerfReport,
  type EvalResult,
  type PerfRow,
} from '../crypto/mpc'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Styles                                                             */
/* ------------------------------------------------------------------ */

const panelStyle: React.CSSProperties = {
  flex: 1,
  padding: 16,
  border: '1px solid var(--border, #444)',
  borderRadius: 8,
  background: 'var(--surface, #1e1e1e)',
}

const btnStyle: React.CSSProperties = {
  appearance: 'none',
  border: '1px solid var(--border, #555)',
  background: 'var(--accent-bg, #2a2a3a)',
  color: 'var(--text-h, #eee)',
  fontFamily: 'inherit',
  fontSize: 13,
  fontWeight: 600,
  padding: '6px 14px',
  borderRadius: 6,
  cursor: 'pointer',
}

const btnActiveStyle: React.CSSProperties = {
  ...btnStyle,
  background: 'var(--accent, #6c6cff)',
  color: '#fff',
}

const codeBlock: React.CSSProperties = {
  background: 'var(--surface, #181818)',
  border: '1px solid var(--border, #333)',
  borderRadius: 6,
  padding: 12,
  fontFamily: 'monospace',
  fontSize: 12,
  overflowX: 'auto',
  whiteSpace: 'pre-wrap',
  lineHeight: 1.5,
}

const tableStyle: React.CSSProperties = {
  width: '100%',
  borderCollapse: 'collapse',
  fontFamily: 'monospace',
  fontSize: 12,
}

const thStyle: React.CSSProperties = {
  textAlign: 'left',
  padding: '6px 10px',
  borderBottom: '2px solid var(--border, #444)',
  fontWeight: 700,
}

const tdStyle: React.CSSProperties = {
  padding: '4px 10px',
  borderBottom: '1px solid var(--border, #333)',
}

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type CircuitTab = 'gt' | 'eq' | 'add'

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Pa20MpcDemo() {
  const N = 4
  const maxVal = (1 << N) - 1

  const [circuitTab, setCircuitTab] = useState<CircuitTab>('gt')
  const [aliceVal, setAliceVal] = useState(7)
  const [bobVal, setBobVal] = useState(3)
  const [result, setResult] = useState<EvalResult | null>(null)
  const [resultText, setResultText] = useState('')
  const [computing, setComputing] = useState(false)
  const [showTrace, setShowTrace] = useState(false)
  const [perfRows, setPerfRows] = useState<PerfRow[] | null>(null)
  const [perfRunning, setPerfRunning] = useState(false)

  const circuitLabel: Record<CircuitTab, string> = {
    gt: "Millionaire's Problem",
    eq: 'Equality',
    add: 'Addition',
  }

  function handleCompute() {
    setComputing(true)
    setResult(null)
    setResultText('')
    // Use setTimeout so the UI can show "computing" state
    setTimeout(() => {
      try {
        const aliceBits = numberToBits(aliceVal, N)
        const bobBits = numberToBits(bobVal, N)

        let circuit
        let text: string
        let res: EvalResult

        switch (circuitTab) {
          case 'gt': {
            circuit = buildGreaterThanCircuit(N)
            res = secureEval(circuit, aliceBits, bobBits)
            const gt = res.outputs[0]
            text = gt === 1
              ? 'Alice is richer (x > y)'
              : aliceVal === bobVal
                ? 'Equal (x = y)'
                : 'Bob is richer (x <= y)'
            break
          }
          case 'eq': {
            circuit = buildEqualityCircuit(N)
            res = secureEval(circuit, aliceBits, bobBits)
            const eq = res.outputs[0]
            text = eq === 1 ? 'Equal (x = y)' : 'Not equal (x != y)'
            break
          }
          case 'add': {
            circuit = buildAdditionCircuit(N)
            res = secureEval(circuit, aliceBits, bobBits)
            const sum = bitsToNumber(res.outputs) & maxVal
            text = `Sum = ${sum}  (mod ${maxVal + 1})`
            break
          }
          default:
            throw new Error('bad tab')
        }

        setResult(res)
        setResultText(text)
      } catch (err) {
        setResultText(`Error: ${err}`)
      }
      setComputing(false)
    }, 20)
  }

  function handlePerf() {
    setPerfRunning(true)
    setPerfRows(null)
    setTimeout(() => {
      const rows = runPerfReport()
      setPerfRows(rows)
      setPerfRunning(false)
    }, 20)
  }

  return (
    <div style={{ padding: 24, maxWidth: 960, margin: '0 auto' }}>
      <h2 style={{ marginTop: 0 }}>PA#20 — 2-Party Secure Computation</h2>
      <p style={{ opacity: 0.7, fontSize: 13, marginBottom: 18 }}>
        Boolean circuit evaluator using PA#19 secure gates (AND via OT, XOR/NOT free).
      </p>

      {/* Circuit selector */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 18 }}>
        {(['gt', 'eq', 'add'] as CircuitTab[]).map(t => (
          <button
            key={t}
            style={circuitTab === t ? btnActiveStyle : btnStyle}
            onClick={() => { setCircuitTab(t); setResult(null); setResultText('') }}
          >
            {circuitLabel[t]}
          </button>
        ))}
      </div>

      {/* Alice | Bob panels */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 18 }}>
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 10px' }}>Alice (x)</h3>
          <label style={{ fontSize: 13 }}>
            Secret value: <strong>{aliceVal}</strong>
          </label>
          <br />
          <input
            type="range"
            min={0}
            max={maxVal}
            value={aliceVal}
            onChange={e => setAliceVal(Number(e.target.value))}
            style={{ width: '100%', marginTop: 6 }}
          />
          <div style={{ fontSize: 11, opacity: 0.5, marginTop: 4 }}>
            Range: 0 .. {maxVal} ({N}-bit)
          </div>
        </div>
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 10px' }}>Bob (y)</h3>
          <label style={{ fontSize: 13 }}>
            Secret value: <strong>{bobVal}</strong>
          </label>
          <br />
          <input
            type="range"
            min={0}
            max={maxVal}
            value={bobVal}
            onChange={e => setBobVal(Number(e.target.value))}
            style={{ width: '100%', marginTop: 6 }}
          />
          <div style={{ fontSize: 11, opacity: 0.5, marginTop: 4 }}>
            Range: 0 .. {maxVal} ({N}-bit)
          </div>
        </div>
      </div>

      {/* Compute button */}
      <div style={{ marginBottom: 18 }}>
        <button style={btnActiveStyle} onClick={handleCompute} disabled={computing}>
          {computing ? 'Computing...' : 'Compute Securely'}
        </button>
      </div>

      {/* Result */}
      {resultText && (
        <div style={{
          ...panelStyle,
          marginBottom: 18,
          borderColor: 'var(--accent, #6c6cff)',
        }}>
          <h3 style={{ margin: '0 0 8px' }}>Result</h3>
          <div style={{ fontSize: 18, fontWeight: 700 }}>{resultText}</div>
          {result && (
            <div style={{ fontSize: 12, opacity: 0.6, marginTop: 6 }}>
              OT calls: {result.otCalls} | Time: {result.timeMs.toFixed(2)} ms |
              Gates evaluated: {result.gateLog.length}
            </div>
          )}
        </div>
      )}

      {/* Circuit trace */}
      {result && (
        <div style={{ marginBottom: 18 }}>
          <button style={btnStyle} onClick={() => setShowTrace(!showTrace)}>
            {showTrace ? 'Hide' : 'Show'} Circuit Trace ({result.gateLog.length} gates)
          </button>
          {showTrace && (
            <div style={{ ...codeBlock, marginTop: 8, maxHeight: 300, overflowY: 'auto' }}>
              {result.gateLog.map(g => (
                <div key={g.gateId}>
                  Gate {String(g.gateId).padStart(3, ' ')} | {g.type.padEnd(5, ' ')} | out={g.output}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Performance section */}
      <div style={{ ...panelStyle, marginBottom: 18 }}>
        <h3 style={{ margin: '0 0 10px' }}>Performance Report</h3>
        <button style={btnStyle} onClick={handlePerf} disabled={perfRunning}>
          {perfRunning ? 'Running...' : 'Run n=4 and n=8 benchmarks'}
        </button>
        {perfRows && (
          <table style={{ ...tableStyle, marginTop: 12 }}>
            <thead>
              <tr>
                <th style={thStyle}>Circuit</th>
                <th style={thStyle}>n=4 OT calls</th>
                <th style={thStyle}>n=4 time (ms)</th>
                <th style={thStyle}>n=8 OT calls</th>
                <th style={thStyle}>n=8 time (ms)</th>
              </tr>
            </thead>
            <tbody>
              {perfRows.map(r => (
                <tr key={r.circuit}>
                  <td style={tdStyle}>{r.circuit}</td>
                  <td style={tdStyle}>{r.n4OtCalls}</td>
                  <td style={tdStyle}>{r.n4TimeMs.toFixed(2)}</td>
                  <td style={tdStyle}>{r.n8OtCalls}</td>
                  <td style={tdStyle}>{r.n8TimeMs.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Proof panel */}
      <div style={panelStyle}>
        <h3 style={{ margin: '0 0 10px' }}>Proof: MPC Completeness</h3>
        <div style={codeBlock}>
{`MPC Completeness
=================
AND + XOR is a universal basis for boolean circuits. Any boolean function
f: {0,1}^n -> {0,1}^m can be expressed as a circuit of AND/XOR/NOT gates.

Since PA#19 provides:
  - Secure AND (via 1-out-of-2 OT from PA#18)
  - Secure XOR (free, via additive sharing over Z_2)
  - Secure NOT (free, local bit flip)

we can securely evaluate ANY boolean function between two parties.
This is the GMW protocol applied to boolean circuits.

Cryptographic Lineage
=====================
PA#20 (MPC)
  -> PA#19 Secure AND gate
    -> PA#18 Oblivious Transfer (Bellare-Micali)
      -> PA#16 ElGamal encryption
        -> PA#13 Miller-Rabin primality test (safe prime generation)
          -> PA#11 Diffie-Hellman (modular exponentiation)
            -> PA#1/PA#2 OWF/PRG/PRF foundations

This completes the full cryptographic stack:
  OWF -> PRG -> PRF -> CPA-Enc -> ElGamal -> OT -> Secure Gates -> MPC
  (one-wayness)  (pseudorandomness)  (public-key)  (2-party computation)`}
        </div>
      </div>
    </div>
  )
}
