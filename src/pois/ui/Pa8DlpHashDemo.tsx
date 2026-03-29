/**
 * PA#8 — DLP-Based Collision-Resistant Hash Function Demo
 */
import { useState, useCallback } from 'react'
import {
  dlpHash,
  dlpHashWithTrace,
  dlpHashTruncated,
  birthdaySortAttack,
  DLP_HHAT,
  type BirthdayResult,
} from '../crypto/dlpHash'
import { DLP_P, DLP_G } from '../crypto/dlp'
import { bytesToHex } from '../utils/hex'
import './poisCliqueExplorer.css'

const BIT_OPTIONS = [8, 10, 12, 14, 16] as const

export default function Pa8DlpHashDemo() {
  // Left panel state
  const [message, setMessage] = useState('Hello, DLP hash!')
  const trace = (() => {
    const enc = new TextEncoder().encode(message)
    return dlpHashWithTrace(enc)
  })()
  const digestHex = bytesToHex(trace.digest)

  // Test messages
  const testMessages = ['abc', 'abd', 'Hello', 'hello', 'test', '']
  const testDigests = testMessages.map((m) => ({
    msg: m === '' ? '(empty)' : m,
    hex: bytesToHex(dlpHash(new TextEncoder().encode(m))),
  }))

  // Right panel state
  const [bits, setBits] = useState<number>(16)
  const [collision, setCollision] = useState<BirthdayResult | null>(null)
  const [hunting, setHunting] = useState(false)

  const runBirthday = useCallback(() => {
    setHunting(true)
    setCollision(null)
    // Use setTimeout to let the UI repaint before the blocking computation
    setTimeout(() => {
      const result = birthdaySortAttack(
        (msg) => dlpHashTruncated(msg, bits),
        bits,
      )
      setCollision(result)
      setHunting(false)
    }, 50)
  }, [bits])

  return (
    <div className="poisApp">
      <div className="topBar">
        <div className="topTitle">
          <span className="topTitleMain">PA#8 DLP Collision-Resistant Hash</span>
          <span className="topTitleSub">
            h(x,y) = g<sup>x</sup> &middot; h&#x0302;<sup>y</sup> mod p &nbsp;|&nbsp; Merkle-Damg&aring;rd
          </span>
        </div>
      </div>

      <div className="mainArea">
        {/* ── Left panel: DLP Hash Live ─────────────────────────────── */}
        <div className="panel" style={{ flex: 1 }}>
          <div className="panelTitle">DLP Hash Live</div>

          <div className="field">
            <label className="fieldLabel">Message (text)</label>
            <input
              className="input"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type a message..."
            />
          </div>

          <div className="field">
            <label className="fieldLabel">DLP_Hash(message)</label>
            <div className="outputBox mono">{digestHex}</div>
          </div>

          {/* Chain visualization */}
          <div className="field">
            <label className="fieldLabel">Chaining values</label>
            {trace.chainingValues.map((cv, i) => (
              <div key={i} className="traceStep">
                <span className="traceKey">
                  {i === 0 ? 'IV' : i === trace.chainingValues.length - 1 ? 'digest' : `z${i}`}
                </span>
                <span className="traceVal mono">{bytesToHex(cv)}</span>
                {i < trace.blocks.length && (
                  <span className="traceBadge">
                    block {i}: {bytesToHex(trace.blocks[i])}
                  </span>
                )}
              </div>
            ))}
          </div>

          {/* Test messages table */}
          <div className="field">
            <label className="fieldLabel">Test messages</label>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '2px 12px' }}>
              {testDigests.map((t) => (
                <div key={t.msg} style={{ display: 'contents' }}>
                  <span className="traceKey">{t.msg}</span>
                  <span className="traceVal mono">{t.hex}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Right panel: Birthday Collision Hunt ──────────────────── */}
        <div className="panel" style={{ flex: 1 }}>
          <div className="panelTitle">Birthday Collision Hunt</div>

          <div className="field">
            <label className="fieldLabel">Truncated hash bits</label>
            <select
              className="select"
              value={bits}
              onChange={(e) => { setBits(Number(e.target.value)); setCollision(null) }}
            >
              {BIT_OPTIONS.map((b) => (
                <option key={b} value={b}>{b} bits (expect ~2^{b / 2} = {Math.pow(2, b / 2)} attempts)</option>
              ))}
            </select>
          </div>

          <div className="field">
            <button
              className="input"
              onClick={runBirthday}
              disabled={hunting}
              style={{ cursor: hunting ? 'wait' : 'pointer', fontWeight: 600, textAlign: 'center' }}
            >
              {hunting ? 'Hunting...' : 'Find Collision'}
            </button>
          </div>

          {collision && (
            <>
              <div className="traceStep">
                <span className="traceBadge traceBadgeOk">Collision found!</span>
              </div>
              <div className="field">
                <div className="traceStep">
                  <span className="traceKey">m1</span>
                  <span className="traceVal mono">{bytesToHex(collision.m1)}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">m2</span>
                  <span className="traceVal mono">{bytesToHex(collision.m2)}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Truncated hash ({bits} bits)</span>
                  <span className="traceVal mono">
                    {collision.hash.toString(16).padStart(Math.ceil(bits / 4), '0')}
                  </span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Messages generated</span>
                  <span className="traceVal">{collision.attempts}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Expected (birthday bound)</span>
                  <span className="traceVal">~2^{bits / 2} = {Math.pow(2, bits / 2)}</span>
                </div>
              </div>
            </>
          )}

          {/* ── Proof / explanation panel ───────────────────────────── */}
          <div className="proofPanel" style={{ marginTop: 16 }}>
            <div className="proofSummary">How it works</div>
            <div className="proofBody">
              <div className="proofStep">
                <div className="proofStepMain">DLP Compression Function</div>
                <div className="proofStepSub">
                  h(x, y) = g<sup>x</sup> &middot; h&#x0302;<sup>y</sup> mod p, where
                  p = {DLP_P.toString()}, g = {DLP_G.toString()}, h&#x0302; = {DLP_HHAT.toString()}.
                  If an adversary finds (x, y) and (x', y') with h(x,y) = h(x',y') and (x,y) != (x',y'),
                  then g<sup>(x-x')</sup> = h&#x0302;<sup>(y'-y)</sup> mod p, which reveals log<sub>g</sub>(h&#x0302;)
                  — solving the discrete log problem.
                </div>
              </div>
              <div className="proofStep">
                <div className="proofStepMain">Merkle-Damg&aring;rd Transform</div>
                <div className="proofStepSub">
                  A collision-resistant compression function h: &#123;0,1&#125;<sup>2n</sup> &rarr; &#123;0,1&#125;<sup>n</sup>
                  gives a collision-resistant hash H for arbitrary-length inputs via iterative chaining with
                  MD-strengthening padding (appending the message length).
                </div>
              </div>
              <div className="proofStep">
                <div className="proofStepMain">Birthday Bound</div>
                <div className="proofStepSub">
                  For an n-bit hash, a generic (black-box) collision search needs O(2<sup>n/2</sup>) evaluations.
                  This is optimal — no algorithm can do better without exploiting the hash structure.
                  The demo truncates the 32-bit output to fewer bits so collisions are found quickly.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
