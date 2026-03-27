/**
 * PA#9 — Birthday Attack Demo
 *
 * Left panel: Live birthday attack (naive or Floyd) on DLP hash truncated to n bits.
 * Right panel: Empirical birthday curve — run 20 trials and compare to 2^(n/2).
 * Bottom: Proof panel with birthday bound analysis and MD5/SHA context.
 */
import { useState, useCallback } from 'react'
import {
  birthdayNaive,
  birthdayFloyd,
  runBirthdayTrials,
  computeTheoretical,
  type BirthdayResult,
  type FloydResult,
} from '../crypto/birthdayAttack'
import { dlpHashTruncated } from '../crypto/dlpHash'
import { bytesToHex } from '../utils/hex'
import './poisCliqueExplorer.css'

const BIT_OPTIONS = [8, 10, 12, 14, 16] as const
type Algorithm = 'naive' | 'floyd'

export default function Pa9BirthdayDemo() {
  // ── Left panel state ────────────────────────────────────────────────
  const [bits, setBits] = useState<number>(10)
  const [algo, setAlgo] = useState<Algorithm>('naive')
  const [running, setRunning] = useState(false)
  const [naiveResult, setNaiveResult] = useState<BirthdayResult | null>(null)
  const [floydResult, setFloydResult] = useState<FloydResult | null>(null)
  const [attackAttempts, setAttackAttempts] = useState<number | null>(null)

  // ── Right panel state ───────────────────────────────────────────────
  const [trialBits, setTrialBits] = useState<number>(8)
  const [trials, setTrials] = useState<number[] | null>(null)
  const [runningTrials, setRunningTrials] = useState(false)

  const theoretical = computeTheoretical(bits)
  const trialTheoretical = computeTheoretical(trialBits)

  // ── Run single attack ───────────────────────────────────────────────
  const runAttack = useCallback(() => {
    setRunning(true)
    setNaiveResult(null)
    setFloydResult(null)
    setAttackAttempts(null)
    setTimeout(() => {
      if (algo === 'naive') {
        const r = birthdayNaive(
          (msg) => dlpHashTruncated(msg, bits),
          bits,
        )
        setNaiveResult(r)
        setAttackAttempts(r.attempts)
      } else {
        const mask = (1 << bits) - 1
        const r = birthdayFloyd(
          (x: number) => {
            const buf = new Uint8Array(4)
            buf[0] = (x >>> 24) & 0xff
            buf[1] = (x >>> 16) & 0xff
            buf[2] = (x >>> 8) & 0xff
            buf[3] = x & 0xff
            return dlpHashTruncated(buf, bits) & mask
          },
          bits,
        )
        setFloydResult(r)
        setAttackAttempts(r.attempts)
      }
      setRunning(false)
    }, 50)
  }, [algo, bits])

  // ── Run empirical trials ────────────────────────────────────────────
  const runTrials = useCallback(() => {
    setRunningTrials(true)
    setTrials(null)
    setTimeout(() => {
      const results = runBirthdayTrials(
        (msg) => dlpHashTruncated(msg, trialBits),
        trialBits,
        20,
      )
      setTrials(results)
      setRunningTrials(false)
    }, 50)
  }, [trialBits])

  const avgTrials = trials ? trials.reduce((a, b) => a + b, 0) / trials.length : 0
  const maxTrial = trials ? Math.max(...trials) : 0

  return (
    <div className="poisApp">
      <div className="topBar">
        <div className="topTitle">
          <span className="topTitleMain">PA#9 Birthday Attack</span>
          <span className="topTitleSub">
            Naive + Floyd's cycle detection on truncated DLP hash &nbsp;|&nbsp; O(2<sup>n/2</sup>) bound
          </span>
        </div>
      </div>

      <div className="mainArea">
        {/* ── Left panel: Live Birthday Attack ─────────────────────── */}
        <div className="panel" style={{ flex: 1 }}>
          <div className="panelTitle">Live Birthday Attack</div>

          <div className="field">
            <label className="fieldLabel">Truncated hash bits (n)</label>
            <div style={{ display: 'flex', gap: 6 }}>
              {BIT_OPTIONS.map((b) => (
                <button
                  key={b}
                  onClick={() => { setBits(b); setNaiveResult(null); setFloydResult(null); setAttackAttempts(null) }}
                  style={{
                    padding: '4px 12px',
                    borderRadius: 6,
                    border: bits === b ? '2px solid var(--accent)' : '1px solid var(--border)',
                    background: bits === b ? 'var(--accent-bg)' : 'transparent',
                    color: 'var(--text-h)',
                    fontWeight: bits === b ? 700 : 400,
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                    fontSize: 13,
                  }}
                >
                  {b}
                </button>
              ))}
            </div>
          </div>

          <div className="field">
            <label className="fieldLabel">Algorithm</label>
            <div style={{ display: 'flex', gap: 6 }}>
              {(['naive', 'floyd'] as const).map((a) => (
                <button
                  key={a}
                  onClick={() => { setAlgo(a); setNaiveResult(null); setFloydResult(null); setAttackAttempts(null) }}
                  style={{
                    padding: '4px 14px',
                    borderRadius: 6,
                    border: algo === a ? '2px solid var(--accent)' : '1px solid var(--border)',
                    background: algo === a ? 'var(--accent-bg)' : 'transparent',
                    color: 'var(--text-h)',
                    fontWeight: algo === a ? 700 : 400,
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                    fontSize: 13,
                  }}
                >
                  {a === 'naive' ? 'Naive (Map)' : "Floyd's Cycle"}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={runAttack}
            disabled={running}
            style={{
              padding: '8px 20px',
              borderRadius: 8,
              border: 'none',
              background: 'var(--accent)',
              color: '#fff',
              fontWeight: 700,
              cursor: running ? 'wait' : 'pointer',
              fontFamily: 'inherit',
              fontSize: 14,
              opacity: running ? 0.6 : 1,
              marginTop: 4,
            }}
          >
            {running ? 'Searching...' : 'Run Attack'}
          </button>

          {/* Expected vs actual */}
          <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-m)' }}>
            <strong>Expected:</strong> 2<sup>{bits}/2</sup> = {Math.round(theoretical.birthdayBound)} attempts
            {attackAttempts !== null && (
              <>
                <br />
                <strong>Actual:</strong> {attackAttempts} attempts
                {' '}({(attackAttempts / theoretical.birthdayBound).toFixed(2)}x expected)
              </>
            )}
          </div>

          {/* Collision result */}
          {naiveResult && (
            <div style={{ marginTop: 12, padding: 10, background: 'var(--surface)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-h)', marginBottom: 6 }}>
                Collision Found!
              </div>
              <table style={{ fontSize: 12, fontFamily: 'monospace', borderCollapse: 'collapse' }}>
                <tbody>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>m1</td><td>0x{bytesToHex(naiveResult.m1)}</td></tr>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>m2</td><td>0x{bytesToHex(naiveResult.m2)}</td></tr>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>hash</td><td>0x{naiveResult.hash.toString(16).padStart(Math.ceil(bits / 4), '0')}</td></tr>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>attempts</td><td>{naiveResult.attempts}</td></tr>
                </tbody>
              </table>
            </div>
          )}

          {floydResult && (
            <div style={{ marginTop: 12, padding: 10, background: 'var(--surface)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-h)', marginBottom: 6 }}>
                Collision Found (Floyd)!
              </div>
              <table style={{ fontSize: 12, fontFamily: 'monospace', borderCollapse: 'collapse' }}>
                <tbody>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>m1</td><td>0x{floydResult.m1.toString(16).padStart(Math.ceil(bits / 4), '0')}</td></tr>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>m2</td><td>0x{floydResult.m2.toString(16).padStart(Math.ceil(bits / 4), '0')}</td></tr>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>hash</td><td>0x{floydResult.hash.toString(16).padStart(Math.ceil(bits / 4), '0')}</td></tr>
                  <tr><td style={{ padding: '2px 8px', color: 'var(--text-m)' }}>attempts</td><td>{floydResult.attempts}</td></tr>
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Right panel: Empirical Birthday Curve ────────────────── */}
        <div className="panel" style={{ flex: 1 }}>
          <div className="panelTitle">Empirical Birthday Curve</div>

          <div className="field">
            <label className="fieldLabel">Bits for trials</label>
            <div style={{ display: 'flex', gap: 6 }}>
              {BIT_OPTIONS.map((b) => (
                <button
                  key={b}
                  onClick={() => { setTrialBits(b); setTrials(null) }}
                  style={{
                    padding: '4px 12px',
                    borderRadius: 6,
                    border: trialBits === b ? '2px solid var(--accent)' : '1px solid var(--border)',
                    background: trialBits === b ? 'var(--accent-bg)' : 'transparent',
                    color: 'var(--text-h)',
                    fontWeight: trialBits === b ? 700 : 400,
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                    fontSize: 13,
                  }}
                >
                  {b}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={runTrials}
            disabled={runningTrials}
            style={{
              padding: '8px 20px',
              borderRadius: 8,
              border: 'none',
              background: 'var(--accent)',
              color: '#fff',
              fontWeight: 700,
              cursor: runningTrials ? 'wait' : 'pointer',
              fontFamily: 'inherit',
              fontSize: 14,
              opacity: runningTrials ? 0.6 : 1,
              marginTop: 4,
            }}
          >
            {runningTrials ? 'Running 20 trials...' : 'Run 20 Trials'}
          </button>

          {trials && (
            <>
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-m)' }}>
                <strong>Theoretical 2<sup>{trialBits}/2</sup>:</strong> {Math.round(trialTheoretical.birthdayBound)}
                &nbsp;&nbsp;|&nbsp;&nbsp;
                <strong>Average:</strong> {Math.round(avgTrials)}
                &nbsp;&nbsp;({(avgTrials / trialTheoretical.birthdayBound).toFixed(2)}x)
              </div>

              {/* Trial table */}
              <div style={{ marginTop: 8, maxHeight: 320, overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th style={{ padding: '4px 8px', textAlign: 'left', color: 'var(--text-m)' }}>Trial</th>
                      <th style={{ padding: '4px 8px', textAlign: 'right', color: 'var(--text-m)' }}>Attempts</th>
                      <th style={{ padding: '4px 8px', textAlign: 'left', color: 'var(--text-m)' }}>Distribution</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trials.map((t, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '3px 8px', fontFamily: 'monospace' }}>{i + 1}</td>
                        <td style={{ padding: '3px 8px', fontFamily: 'monospace', textAlign: 'right' }}>{t}</td>
                        <td style={{ padding: '3px 8px' }}>
                          <div
                            style={{
                              height: 12,
                              width: `${Math.min(100, (t / maxTrial) * 100)}%`,
                              background: t <= trialTheoretical.birthdayBound * 1.5
                                ? 'var(--accent)'
                                : '#e67e22',
                              borderRadius: 3,
                              minWidth: 4,
                            }}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Bottom: Proof panel ───────────────────────────────────── */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panelTitle">Birthday Bound Analysis</div>
        <div style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-m)' }}>
          <p>
            <strong>Birthday bound:</strong> For a hash function H: &#123;0,1&#125;* &#8594; &#123;0,1&#125;<sup>n</sup>,
            a collision is expected after approximately <strong>2<sup>n/2</sup></strong> evaluations.
            This follows from the birthday paradox: among k random samples from a set of size N = 2<sup>n</sup>,
            the probability of at least one collision is approximately 1 - e<sup>-k<sup>2</sup>/(2N)</sup>.
            Setting this to 0.5 gives k &#8776; 1.177 * 2<sup>n/2</sup>.
          </p>
          <p>
            <strong>Tightness:</strong> The bound is tight. Any generic (black-box) collision-finding algorithm
            requires &#937;(2<sup>n/2</sup>) hash evaluations. The naive Map-based approach achieves this
            with O(2<sup>n/2</sup>) space; Floyd's cycle detection achieves it with O(1) space (but only
            works when treating the hash as an endomorphism on its own range).
          </p>
          <p>
            <strong>Real-world context (at 10<sup>9</sup> hashes/sec):</strong>
          </p>
          <table style={{ fontSize: 12, fontFamily: 'monospace', borderCollapse: 'collapse', marginTop: 4 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={{ padding: '3px 10px', textAlign: 'left' }}>Hash</th>
                <th style={{ padding: '3px 10px', textAlign: 'right' }}>n (bits)</th>
                <th style={{ padding: '3px 10px', textAlign: 'right' }}>2<sup>n/2</sup></th>
                <th style={{ padding: '3px 10px', textAlign: 'right' }}>Time</th>
              </tr>
            </thead>
            <tbody>
              {([
                { name: 'MD5', n: 128 },
                { name: 'SHA-1', n: 160 },
                { name: 'SHA-256', n: 256 },
                { name: 'SHA-512', n: 512 },
              ] as const).map(({ name, n }) => {
                const t = computeTheoretical(n)
                return (
                  <tr key={name} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '3px 10px' }}>{name}</td>
                    <td style={{ padding: '3px 10px', textAlign: 'right' }}>{n}</td>
                    <td style={{ padding: '3px 10px', textAlign: 'right' }}>2^{n / 2}</td>
                    <td style={{ padding: '3px 10px', textAlign: 'right' }}>{t.humanReadable}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          <p style={{ marginTop: 8 }}>
            <strong>MD5</strong> (128-bit) has a birthday bound of 2<sup>64</sup> &#8776; 1.8 x 10<sup>19</sup>, achievable in ~585 years at 10<sup>9</sup> H/s.
            In practice, structural weaknesses allow much faster attacks (Wang et al., 2004).
            <strong> SHA-1</strong> (160-bit) was broken by SHAttered (Stevens et al., 2017) in 2<sup>63.1</sup> computations,
            well below its 2<sup>80</sup> birthday bound, exploiting differential paths.
          </p>
        </div>
      </div>
    </div>
  )
}
