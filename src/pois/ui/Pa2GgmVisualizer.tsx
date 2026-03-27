/**
 * PA2 Demo: GGM PRF visualizer.
 * Shows the full binary tree expansion and highlights the evaluation path.
 */

import { useState, useMemo, useCallback } from 'react'
import { makeAesPRF, makeGgmPRF, ggmEvaluateWithTrace, runDistinguishingGame } from '../crypto/prf'
import { makeAesGgmSplitPrg } from '../crypto/prg'
import { parseFlexibleInputToBytes, bytesToHex } from '../utils/hex'
import type { DistinguishingResult } from '../crypto/prf'
import './poisCliqueExplorer.css'

const PRF_OPTIONS = [
  { id: 'ggm', label: 'GGM PRF (from PRG → tree)' },
  { id: 'aes', label: 'AES plug-in PRF  F_k(x) = AES_k(x)' },
] as const
type PrfId = (typeof PRF_OPTIONS)[number]['id']

function bitsFromHex(hex: string, maxBits: number): number[] {
  const clean = hex.replace(/\s/g, '')
  const bits: number[] = []
  for (let i = 0; i < clean.length && bits.length < maxBits; i += 2) {
    const byte = parseInt(clean.slice(i, i + 2) || '00', 16)
    for (let b = 7; b >= 0 && bits.length < maxBits; b--) {
      bits.push((byte >> b) & 1)
    }
  }
  while (bits.length < maxBits) bits.push(0)
  return bits
}

// ── SVG GGM tree ─────────────────────────────────────────────────────────────

const NODE_W = 60
const NODE_H = 26
const LEVEL_H = 62

function nodeX(index: number, depth: number, totalDepth: number, svgW: number) {
  const nodesAtLeaf = Math.pow(2, totalDepth)
  const groupSize = nodesAtLeaf / Math.pow(2, depth)
  const spacing = svgW / nodesAtLeaf
  return spacing * groupSize * index + spacing * groupSize * 0.5
}

function nodeY(depth: number) { return 20 + depth * LEVEL_H }

interface GgmSvgProps { queryBits: number[]; keyHex: string }

function GgmSvgTree({ queryBits, keyHex }: GgmSvgProps) {
  const depth = queryBits.length
  const keyBytes = useMemo(() => parseFlexibleInputToBytes(keyHex), [keyHex])

  // Fast 2-AES-call PRG — no HILL construction here
  const fastPrg = useMemo(() => makeAesGgmSplitPrg(), [])

  const { nodes } = useMemo(
    () => ggmEvaluateWithTrace(fastPrg, keyBytes, queryBits),
    [fastPrg, keyBytes, queryBits]
  )

  const maxLeaves = Math.pow(2, depth)
  const svgW = Math.max(maxLeaves * (NODE_W + 10) + 10, 200)
  const svgH = (depth + 1) * LEVEL_H + 30

  return (
    <svg
      width="100%"
      viewBox={`0 0 ${svgW} ${svgH}`}
      style={{ display: 'block', overflow: 'visible' }}
    >
      {/* Edges */}
      {nodes.map(n => {
        if (n.depth === 0) return null
        const px = nodeX(Math.floor(n.index / 2), n.depth - 1, depth, svgW)
        const py = nodeY(n.depth - 1) + NODE_H
        const cx = nodeX(n.index, n.depth, depth, svgW)
        const cy = nodeY(n.depth)
        return (
          <line
            key={`e-${n.depth}-${n.index}`}
            x1={px} y1={py} x2={cx} y2={cy + NODE_H / 2}
            stroke={n.onPath ? 'var(--accent)' : 'var(--border)'}
            strokeWidth={n.onPath ? 2 : 1}
            strokeDasharray={n.onPath ? undefined : '4 3'}
            opacity={n.onPath ? 1 : 0.4}
          />
        )
      })}

      {/* Bit labels on path edges */}
      {queryBits.map((bit, d) => {
        const child = nodes.find(n => n.depth === d + 1 && n.onPath)
        if (!child) return null
        const cx = nodeX(child.index, d + 1, depth, svgW)
        const px = nodeX(Math.floor(child.index / 2), d, depth, svgW)
        return (
          <text
            key={`bl-${d}`}
            x={(cx + px) / 2 + 7}
            y={(nodeY(d + 1) + nodeY(d) + NODE_H) / 2 - 2}
            fontSize={10} fill="var(--accent)" fontWeight={700}
          >{bit}</text>
        )
      })}

      {/* Nodes */}
      {nodes.map(n => {
        const cx = nodeX(n.index, n.depth, depth, svgW)
        const cy = nodeY(n.depth)
        const isResult = n.isLeaf && n.onPath
        return (
          <g key={`n-${n.depth}-${n.index}`}>
            <rect
              x={cx - NODE_W / 2} y={cy} width={NODE_W} height={NODE_H} rx={6}
              fill={isResult ? 'var(--accent)' : n.onPath ? 'var(--accent-bg)' : 'var(--surface-soft)'}
              stroke={n.onPath ? 'var(--accent)' : 'var(--border)'}
              strokeWidth={n.onPath ? 1.5 : 1}
              opacity={n.onPath ? 1 : 0.45}
            />
            <text
              x={cx} y={cy + NODE_H / 2 + 4}
              textAnchor="middle" fontSize={9}
              fontFamily="var(--mono)"
              fill={isResult ? '#fff' : 'var(--text-h)'}
              opacity={n.onPath ? 1 : 0.55}
            >{n.valueHex}</text>
          </g>
        )
      })}
    </svg>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Pa2GgmVisualizer() {
  const [prfId, setPrfId] = useState<PrfId>('ggm')
  const [keyHex, setKeyHex] = useState('0123456789abcdef')
  const [queryHex, setQueryHex] = useState('ab')
  const [treeDepth, setTreeDepth] = useState(4)

  // Distinguishing game: button-triggered only (expensive)
  const [distQueries, setDistQueries] = useState(200)
  const [distResult, setDistResult] = useState<DistinguishingResult | null>(null)
  const [distRunning, setDistRunning] = useState(false)

  const keyBytes = useMemo(() => parseFlexibleInputToBytes(keyHex), [keyHex])
  const queryBytes = useMemo(() => parseFlexibleInputToBytes(queryHex), [queryHex])
  const queryBits = useMemo(() => bitsFromHex(queryHex, treeDepth), [queryHex, treeDepth])

  // PRF oracle — for AES this is trivial; for GGM use the fast split PRG
  const prfOracle = useMemo(() => {
    if (prfId === 'aes') return makeAesPRF(keyBytes)
    return makeGgmPRF(makeAesGgmSplitPrg(), keyBytes)
  }, [prfId, keyBytes])

  const prfOutput = useMemo(() => {
    try { return prfOracle.evaluate(queryBytes) } catch { return new Uint8Array(16) }
  }, [prfOracle, queryBytes])

  const runDistGame = useCallback(() => {
    setDistRunning(true)
    // Yield to the browser to repaint the "running…" state before blocking
    setTimeout(() => {
      setDistResult(runDistinguishingGame(prfOracle, distQueries))
      setDistRunning(false)
    }, 20)
  }, [prfOracle, distQueries])

  const verdict = distResult?.verdict

  return (
    <div className="poisApp">
      <div className="topBar" style={{ marginBottom: 14 }}>
        <div className="topTitle">
          <div className="topTitleMain">PA2 — PRF &amp; GGM Visualizer</div>
          <div className="topTitleSub">GGM tree construction · AES plug-in PRF · distinguishing game</div>
        </div>
      </div>

      <div className="mainArea">
        {/* ── Left: controls ── */}
        <div className="panel">
          <div className="panelTitle">PRF Evaluation</div>

          <label className="field">
            <div className="fieldLabel">PRF Type</div>
            <select className="select" value={prfId} onChange={e => { setPrfId(e.target.value as PrfId); setDistResult(null) }}>
              {PRF_OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
            </select>
          </label>

          <label className="field">
            <div className="fieldLabel">Key k (hex)</div>
            <input className="input" value={keyHex}
              onChange={e => { setKeyHex(e.target.value); setDistResult(null) }}
              spellCheck={false} placeholder="16 hex bytes" />
          </label>

          <label className="field">
            <div className="fieldLabel">Query x (hex)</div>
            <input className="input" value={queryHex}
              onChange={e => setQueryHex(e.target.value)}
              spellCheck={false} placeholder="e.g. ab" />
          </label>

          {prfId === 'ggm' && (
            <label className="field">
              <div className="fieldLabel">Tree depth: {treeDepth} ({Math.pow(2, treeDepth)} leaves)</div>
              <input type="range" min={1} max={6} value={treeDepth}
                onChange={e => setTreeDepth(Number(e.target.value))}
                style={{ width: '100%' }} />
            </label>
          )}

          {/* Output */}
          <div className="outputBox" style={{ marginTop: 8 }}>
            <div style={{ fontSize: 12, opacity: 0.7, marginBottom: 4 }}>F_k(x)</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 13, wordBreak: 'break-all', color: 'var(--text-h)' }}>
              {bytesToHex(prfOutput)}
            </div>
          </div>

          {/* Distinguishing game */}
          <div style={{ marginTop: 16 }}>
            <div className="panelTitle" style={{ marginBottom: 8 }}>Distinguishing Game</div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
              <label className="field" style={{ flex: 1, margin: 0 }}>
                <div className="fieldLabel">Queries: {distQueries}</div>
                <input type="range" min={50} max={500} step={50} value={distQueries}
                  onChange={e => { setDistQueries(Number(e.target.value)); setDistResult(null) }}
                  style={{ width: '100%' }} />
              </label>
              <button
                onClick={runDistGame}
                disabled={distRunning}
                style={{
                  marginTop: 18,
                  padding: '8px 14px',
                  borderRadius: 8,
                  border: '1px solid var(--accent-border)',
                  background: 'var(--accent-bg)',
                  color: 'var(--text-h)',
                  fontFamily: 'inherit',
                  fontWeight: 700,
                  fontSize: 13,
                  cursor: distRunning ? 'wait' : 'pointer',
                  whiteSpace: 'nowrap',
                }}
              >
                {distRunning ? 'Running…' : 'Run test'}
              </button>
            </div>

            {distResult ? (
              <div style={{
                padding: '10px 12px', borderRadius: 10,
                border: `1px solid ${verdict === 'indistinguishable' ? 'var(--surface-stroke)' : '#f87171'}`,
                background: verdict === 'indistinguishable' ? 'var(--surface-soft)' : 'rgba(248,113,113,0.08)',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-h)' }}>χ² test vs. uniform</span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: verdict === 'indistinguishable' ? 'var(--accent)' : '#f87171' }}>
                    {verdict === 'indistinguishable' ? 'Indistinguishable' : 'Distinguishable'}
                  </span>
                </div>
                <div style={{ fontSize: 12, opacity: 0.75, marginTop: 4, fontFamily: 'var(--mono)' }}>
                  χ² = {distResult.chiSquaredStat.toFixed(2)} · p = {distResult.pValue.toFixed(4)} · {distResult.queriesRun} queries
                </div>
              </div>
            ) : (
              <div style={{ fontSize: 12, opacity: 0.5 }}>Press "Run test" to evaluate.</div>
            )}
          </div>
        </div>

        {/* ── Right: GGM tree SVG ── */}
        <div className="panel" style={{ overflowX: 'auto' }}>
          <div className="panelTitle">
            GGM Tree
            {prfId !== 'ggm' && <span style={{ fontSize: 12, opacity: 0.6, fontWeight: 400 }}> (switch to GGM PRF)</span>}
          </div>
          {prfId === 'ggm' ? (
            <>
              <div style={{ fontSize: 12, opacity: 0.7, marginBottom: 8 }}>
                Query bits: <span style={{ fontFamily: 'var(--mono)' }}>[{queryBits.join(', ')}]</span> — highlighted path root→leaf
              </div>
              <GgmSvgTree queryBits={queryBits} keyHex={keyHex} />
              <div style={{ marginTop: 10, fontSize: 12, opacity: 0.65, lineHeight: 1.55 }}>
                <strong>Construction:</strong> {'F_k(b₁…bₙ) = G_{bₙ}(…G_{b₁}(k)…)'}<br />
                G(v) = AES_v(0) ‖ AES_v(1) — left/right children.<br />
                Colored nodes are on the path for [{queryBits.join('')}]₂.
              </div>
            </>
          ) : (
            <div style={{ padding: '40px 0', textAlign: 'center', opacity: 0.45 }}>
              Select "GGM PRF" to visualize the tree.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
