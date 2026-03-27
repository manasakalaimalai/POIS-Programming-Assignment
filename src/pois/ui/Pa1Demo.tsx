/**
 * PA1 Demo: OWF + PRG live playground.
 * - Choose OWF (AES Davies-Meyer or DLP)
 * - Enter a seed
 * - Slide to pick output length
 * - See live HILL-PRG output
 * - Run NIST randomness tests on the output
 */

import { useState, useMemo, useEffect } from 'react'
import { makeAesOwfOracle, makeDlpOwfOracle } from '../crypto/owf'
import { hillGenerate } from '../crypto/prg'
import { runAllStatTests } from '../stats/randomness'
import { parseFlexibleInputToBytes, bytesToHex } from '../utils/hex'
import './poisCliqueExplorer.css'

const OWF_OPTIONS = [
  { id: 'aes', label: 'AES Davies-Meyer  f(k) = AES_k(0¹²⁸) ⊕ k' },
  { id: 'dlp', label: 'DLP  f(x) = 2^x mod 1,073,741,827' },
] as const

type OwfId = (typeof OWF_OPTIONS)[number]['id']

function hexGrid(hex: string, bytesPerRow = 16) {
  const rows: string[] = []
  for (let i = 0; i < hex.length; i += bytesPerRow * 2) {
    rows.push(hex.slice(i, i + bytesPerRow * 2))
  }
  return rows
}

export default function Pa1Demo() {
  const [owfId, setOwfId] = useState<OwfId>('aes')
  const [seedRaw, setSeedRaw] = useState('deadbeef')
  const [outputBytesSlider, setOutputBytesSlider] = useState(32)
  const [outputBytes, setOutputBytes] = useState(32)

  // Debounce slider: only recompute 200ms after user stops dragging
  useEffect(() => {
    const t = setTimeout(() => setOutputBytes(outputBytesSlider), 200)
    return () => clearTimeout(t)
  }, [outputBytesSlider])

  const seedBytes = useMemo(() => {
    try { return parseFlexibleInputToBytes(seedRaw) } catch { return new Uint8Array([0xde, 0xad, 0xbe, 0xef]) }
  }, [seedRaw])

  const owfOracle = useMemo(
    () => (owfId === 'dlp' ? makeDlpOwfOracle() : makeAesOwfOracle()),
    [owfId]
  )

  const prgOutput = useMemo(
    () => hillGenerate(owfOracle, seedBytes, outputBytes),
    [owfOracle, seedBytes, outputBytes]
  )

  const prgHex = useMemo(() => bytesToHex(prgOutput), [prgOutput])

  const statResults = useMemo(() => runAllStatTests(prgOutput), [prgOutput])

  const allPass = statResults.every(r => r.pass)

  return (
    <div className="poisApp">
      {/* header */}
      <div className="topBar" style={{ marginBottom: 14 }}>
        <div className="topTitle">
          <div className="topTitleMain">PA1 — OWF &amp; PRG Demo</div>
          <div className="topTitleSub">HILL construction · AES Davies-Meyer · DLP · NIST randomness tests</div>
        </div>
      </div>

      <div className="mainArea">
        {/* ── Left: controls ── */}
        <div className="panel">
          <div className="panelTitle">Parameters</div>

          {/* OWF choice */}
          <label className="field">
            <div className="fieldLabel">One-Way Function</div>
            <select
              className="select"
              value={owfId}
              onChange={e => setOwfId(e.target.value as OwfId)}
            >
              {OWF_OPTIONS.map(o => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
          </label>

          {/* Seed */}
          <label className="field">
            <div className="fieldLabel">Seed (hex or ASCII)</div>
            <input
              className="input"
              value={seedRaw}
              onChange={e => setSeedRaw(e.target.value)}
              placeholder="e.g. deadbeef or hello"
              spellCheck={false}
            />
          </label>
          <div style={{ fontSize: 12, opacity: 0.7, marginTop: -8, marginBottom: 12 }}>
            Parsed: {bytesToHex(seedBytes)} ({seedBytes.length}B)
          </div>

          {/* Output length slider */}
          <label className="field">
            <div className="fieldLabel">PRG output length: {outputBytesSlider} bytes ({outputBytesSlider * 8} bits)</div>
            <input
              type="range"
              min={8}
              max={256}
              step={8}
              value={outputBytesSlider}
              onChange={e => setOutputBytesSlider(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </label>

          {/* OWF info */}
          <div style={{
            marginTop: 8,
            padding: '10px 12px',
            borderRadius: 10,
            background: 'var(--surface-soft)',
            border: '1px solid var(--border)',
            fontSize: 12,
            lineHeight: 1.55,
          }}>
            <strong>HILL construction:</strong><br />
            {'G(x₀) = b(x₀) ‖ b(x₁) ‖ … ‖ b(x_{ℓ−1})'}<br />
            {'where x_{i+1} = f(x_i) and b(x) = LSB of f(x).'}<br />
            <br />
            <strong>Expansion:</strong> {seedBytes.length}B seed → {outputBytes}B output
            ({(outputBytes / Math.max(1, seedBytes.length)).toFixed(1)}× stretch)
          </div>
        </div>

        {/* ── Right: PRG output ── */}
        <div className="panel">
          <div className="panelTitle">PRG Output</div>
          <div style={{
            fontFamily: 'var(--mono)',
            fontSize: 11,
            lineHeight: 1.7,
            wordBreak: 'break-all',
            maxHeight: 240,
            overflowY: 'auto',
            padding: '8px 10px',
            background: 'var(--surface-soft)',
            border: '1px solid var(--border)',
            borderRadius: 10,
          }}>
            {hexGrid(prgHex).map((row, i) => (
              <div key={i} style={{ display: 'flex', gap: 8 }}>
                <span style={{ opacity: 0.4, minWidth: 28, textAlign: 'right' }}>{(i * 16).toString(16).padStart(3, '0')}</span>
                <span>
                  {row.match(/.{1,2}/g)?.map((b, j) => (
                    <span key={j} style={{ marginRight: 4 }}>{b}</span>
                  ))}
                </span>
              </div>
            ))}
          </div>

          {/* NIST test results */}
          <div style={{ marginTop: 14 }}>
            <div className="panelTitle" style={{ marginBottom: 8 }}>
              NIST SP 800-22 Randomness Tests
              <span style={{
                marginLeft: 10,
                fontSize: 12,
                color: allPass ? 'var(--accent)' : '#f87171',
                fontWeight: 700,
              }}>
                {allPass ? '✓ All pass' : '✗ Some fail'}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {statResults.map(r => (
                <div key={r.testName} style={{
                  padding: '8px 12px',
                  borderRadius: 10,
                  border: `1px solid ${r.pass ? 'var(--surface-stroke)' : '#f87171'}`,
                  background: r.pass ? 'var(--surface-soft)' : 'rgba(248,113,113,0.08)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-h)' }}>
                      {r.testName}
                    </span>
                    <span style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: r.pass ? 'var(--accent)' : '#f87171',
                    }}>
                      {r.pass ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                  <div style={{ fontSize: 12, opacity: 0.8, marginTop: 3 }}>
                    p-value = {r.pValue.toFixed(4)}{r.pValue < 0.01 ? ' (< 0.01 threshold)' : ''}
                  </div>
                  <div style={{ fontSize: 11, opacity: 0.65, marginTop: 2, fontFamily: 'var(--mono)' }}>
                    {r.detail}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
