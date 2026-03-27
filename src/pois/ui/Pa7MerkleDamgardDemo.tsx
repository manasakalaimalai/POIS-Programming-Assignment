/**
 * PA#7 Demo — Merkle-Damgard Chain Viewer
 */

import { useState, useMemo } from 'react'
import {
  merkleDamgardWithTrace,
  toyCompress,
  TOY_IV,
  TOY_BLOCK_SIZE,
  COLLISION_MSG_A,
  COLLISION_MSG_B,
} from '../crypto/merkleDamgard'
import { bytesToHex } from '../utils/hex'
import './poisCliqueExplorer.css'

type InputMode = 'text' | 'hex'

function hexToUint8(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '')
  if (clean.length === 0) return new Uint8Array()
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error('Invalid hex')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16)
  }
  return out
}

// ── Chain visualization row ─────────────────────────────────────────────────

function ChainRow({ trace }: { trace: ReturnType<typeof merkleDamgardWithTrace> }) {
  return (
    <div style={{ overflowX: 'auto', padding: '10px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 'max-content' }}>
        {trace.chainingValues.map((cv, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {/* chaining value box */}
            <div className="traceStep" style={{ minWidth: 80, textAlign: 'center' }}>
              <span className="traceKey">z{'\u2080' + String.fromCharCode(0x2080 + i).slice(-1)}</span>
              {i === 0 && <span className="traceBadge">IV</span>}
              {i === trace.chainingValues.length - 1 && <span className="traceBadgeOk">digest</span>}
              <br />
              <span className="mono" style={{ fontSize: 11 }}>{bytesToHex(cv)}</span>
            </div>
            {/* arrow + block label */}
            {i < trace.blocks.length && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <span style={{ fontSize: 10, color: 'var(--text-m)', fontFamily: 'var(--font-mono, monospace)' }}>
                  M{i + 1}
                </span>
                <span style={{ fontSize: 16, color: 'var(--accent)' }}>{'\u2192'}</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Subscript helper ────────────────────────────────────────────────────────

function sub(n: number): string {
  const subs = '\u2080\u2081\u2082\u2083\u2084\u2085\u2086\u2087\u2088\u2089'
  return String(n).split('').map(c => subs[parseInt(c)] || c).join('')
}

// ── Main component ──────────────────────────────────────────────────────────

export default function Pa7MerkleDamgardDemo() {
  const [inputMode, setInputMode] = useState<InputMode>('text')
  const [rawInput, setRawInput] = useState('hello')

  const messageBytes = useMemo(() => {
    try {
      if (inputMode === 'hex') return hexToUint8(rawInput)
      return new TextEncoder().encode(rawInput)
    } catch {
      return new Uint8Array()
    }
  }, [rawInput, inputMode])

  const trace = useMemo(
    () => merkleDamgardWithTrace(messageBytes, toyCompress, TOY_IV, TOY_BLOCK_SIZE),
    [messageBytes],
  )

  // Collision demo
  const collision = useMemo(() => {
    const tA = merkleDamgardWithTrace(COLLISION_MSG_A, toyCompress, TOY_IV, TOY_BLOCK_SIZE)
    const tB = merkleDamgardWithTrace(COLLISION_MSG_B, toyCompress, TOY_IV, TOY_BLOCK_SIZE)
    return { tA, tB }
  }, [])

  return (
    <div className="poisApp">
      <div className="topBar">
        <div className="topTitle">
          <span className="topTitleMain">PA7 — Merkle-Damgard Transform</span>
          <span className="topTitleSub">Chain viewer with toy XOR compression (block=8, cv=4 bytes)</span>
        </div>
      </div>

      <div className="mainArea" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 18 }}>
        {/* ── Input panel ─────────────────────────────────────────── */}
        <div className="panel">
          <div className="panelTitle">Message Input</div>
          <div className="field" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <label className="fieldLabel" style={{ minWidth: 50 }}>Mode</label>
            <select
              className="select"
              value={inputMode}
              onChange={e => setInputMode(e.target.value as InputMode)}
            >
              <option value="text">Text (UTF-8)</option>
              <option value="hex">Hex</option>
            </select>
            <input
              className="input"
              style={{ flex: 1, minWidth: 200 }}
              value={rawInput}
              onChange={e => setRawInput(e.target.value)}
              placeholder={inputMode === 'hex' ? '0102030405...' : 'Type a message...'}
            />
          </div>
          <div className="field">
            <span className="fieldLabel">Raw bytes ({messageBytes.length}B):</span>
            <span className="mono" style={{ fontSize: 12 }}>{bytesToHex(messageBytes) || '(empty)'}</span>
          </div>
        </div>

        {/* ── Blocks after padding ────────────────────────────────── */}
        <div className="panel">
          <div className="panelTitle">Blocks After MD Padding</div>
          <div className="field">
            <span className="fieldLabel">
              Padded length: {trace.paddedMessage.length}B ({trace.blocks.length} block{trace.blocks.length !== 1 ? 's' : ''})
            </span>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {trace.blocks.map((blk, i) => (
              <div key={i} className="traceStep" style={{ textAlign: 'center' }}>
                <div className="traceHeader">M{sub(i + 1)}</div>
                <div className="mono" style={{ fontSize: 11, wordBreak: 'break-all', maxWidth: 140 }}>
                  {bytesToHex(blk)}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Chain visualization ─────────────────────────────────── */}
        <div className="panel">
          <div className="panelTitle">Chaining Visualization</div>
          <ChainRow trace={trace} />
          <div className="outputBox" style={{ marginTop: 10 }}>
            <span className="traceKey">H(M) = </span>
            <span className="mono">{bytesToHex(trace.digest)}</span>
          </div>
        </div>

        {/* ── Collision propagation ───────────────────────────────── */}
        <div className="panel">
          <div className="panelTitle">Collision Propagation Demo</div>
          <p className="traceNote" style={{ margin: '0 0 8px' }}>
            Two messages whose 8-byte blocks have swapped halves collide under
            toyCompress (XOR is commutative). The MD construction propagates this
            into a collision on the full hash.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              { label: 'Message A', msg: COLLISION_MSG_A, t: collision.tA },
              { label: 'Message B', msg: COLLISION_MSG_B, t: collision.tB },
            ].map(({ label, msg, t }) => (
              <div key={label}>
                <div className="traceBlockHeader">
                  {label}: <span className="mono">{bytesToHex(msg)}</span>
                </div>
                <ChainRow trace={t} />
              </div>
            ))}
          </div>
          <div className="outputBox" style={{ marginTop: 8 }}>
            <span className="traceKey">H(A) = </span><span className="mono">{bytesToHex(collision.tA.digest)}</span>
            <span style={{ margin: '0 8px', color: 'var(--text-m)' }}>|</span>
            <span className="traceKey">H(B) = </span><span className="mono">{bytesToHex(collision.tB.digest)}</span>
            <span style={{ margin: '0 8px' }}>
              {bytesToHex(collision.tA.digest) === bytesToHex(collision.tB.digest)
                ? <span className="traceBadgeOk">COLLISION</span>
                : <span className="traceBadge">different</span>}
            </span>
          </div>
        </div>

        {/* ── Proof panel ─────────────────────────────────────────── */}
        <div className="proofPanel">
          <details>
            <summary className="proofSummary">Why does this work? (Proof sketch)</summary>
            <div className="proofBody">
              <div className="proofStep">
                <div className="proofStepMain">MD Transform Security</div>
                <div className="proofStepSub">
                  If the compression function h is collision-resistant, then the
                  full Merkle-Damgard hash H is also collision-resistant. Proof
                  by contrapositive: any collision H(M) = H(M') with M {'\u2260'} M'
                  can be traced backwards through the chain to find a collision
                  on h.
                </div>
              </div>
              <div className="proofStep">
                <div className="proofStepMain">Collision Propagation</div>
                <div className="proofStepSub">
                  Given H(M) = H(M'), the final chaining values match:
                  h(z{'_{n-1}'}, M_n) = h(z'{`_{m-1}`}', M'_m). Walking backwards,
                  either (z{'_{i-1}'}, M_i) {'\u2260'} (z'{`_{i-1}`}', M'_i) — giving
                  a direct h-collision — or all chaining values and blocks match,
                  contradicting M {'\u2260'} M'.
                </div>
              </div>
              <div className="proofStep">
                <div className="proofStepMain">MD-Strengthening Padding</div>
                <div className="proofStepSub">
                  Appending the message length in the final block prevents trivial
                  collisions from messages of different lengths. Without it, M and
                  M || 0{'\u2080'}...0 could collide since padding might align them to
                  the same blocks. The length suffix ensures differently-sized
                  messages always differ in at least one block.
                </div>
              </div>
            </div>
          </details>
        </div>
      </div>
    </div>
  )
}
