/**
 * PA3 Demo: CPA-Secure Symmetric Encryption
 * Interactive IND-CPA game + nonce reuse attack demonstration.
 */

import { useState, useMemo, useCallback } from 'react'
import { makeAesPRF, makeGgmPRF } from '../crypto/prf'
import { makeAesGgmSplitPrg } from '../crypto/prg'
import { cpaEncrypt, cpaDecrypt, indCpaChallenge, nonceReuseAttack } from '../crypto/cpaEnc'
import { parseFlexibleInputToBytes, bytesToHex } from '../utils/hex'
import type { PrimitiveOracle } from '../types'
import './poisCliqueExplorer.css'

const PRF_OPTIONS = [
  { id: 'aes', label: 'AES plug-in PRF  F_k(x) = AES_k(x)' },
  { id: 'ggm', label: 'GGM PRF (from PRG tree)' },
] as const
type PrfId = (typeof PRF_OPTIONS)[number]['id']

type GameState =
  | { phase: 'input' }
  | { phase: 'challenge'; b: number; rHex: string; ctHex: string }
  | { phase: 'revealed'; b: number; guess: number; correct: boolean; rHex: string; ctHex: string }

export default function Pa3CpaDemo() {
  const [prfId, setPrfId] = useState<PrfId>('aes')
  const [keyHex, setKeyHex] = useState('0123456789abcdef0123456789abcdef')
  const [m0Text, setM0Text] = useState('Hello, World!!!')  // 15 chars → fits in 1 block
  const [m1Text, setM1Text] = useState('Goodbye World!!')
  const [reuseNonce, setReuseNonce] = useState(false)

  // IND-CPA game state
  const [game, setGame] = useState<GameState>({ phase: 'input' })
  const [rounds, setRounds] = useState<{ correct: boolean }[]>([])

  // Nonce reuse attack state
  const [attackResult, setAttackResult] = useState<{
    c0Hex: string; c1Hex: string; xorCtHex: string; xorPtHex: string; match: boolean
  } | null>(null)

  // Build PRF oracle
  const prfOracle: PrimitiveOracle | null = useMemo(() => {
    try {
      const keyBytes = parseFlexibleInputToBytes(keyHex)
      if (keyBytes.length < 16) return null
      const key16 = keyBytes.slice(0, 16)

      if (prfId === 'aes') {
        return makeAesPRF(key16)
      } else {
        const fastPrg = makeAesGgmSplitPrg()
        return makeGgmPRF(fastPrg, key16)
      }
    } catch {
      return null
    }
  }, [prfId, keyHex])

  // Basic encrypt/decrypt demo
  const encDemo = useMemo(() => {
    if (!prfOracle) return null
    try {
      const m0 = new TextEncoder().encode(m0Text)
      const { r, ciphertext } = cpaEncrypt(prfOracle, m0)
      const decrypted = cpaDecrypt(prfOracle, r, ciphertext)
      return {
        rHex: bytesToHex(r),
        ctHex: bytesToHex(ciphertext),
        decHex: bytesToHex(decrypted),
        decText: new TextDecoder().decode(decrypted),
        ok: new TextDecoder().decode(decrypted) === m0Text,
      }
    } catch {
      return null
    }
  }, [prfOracle, m0Text])

  // IND-CPA game: start challenge
  const startChallenge = useCallback(() => {
    if (!prfOracle) return
    const m0 = new TextEncoder().encode(m0Text)
    const m1 = new TextEncoder().encode(m1Text)
    // Pad to equal length
    const maxLen = Math.max(m0.length, m1.length)
    const m0p = new Uint8Array(maxLen)
    const m1p = new Uint8Array(maxLen)
    m0p.set(m0); m1p.set(m1)

    const { b, challengeCiphertext } = indCpaChallenge(prfOracle, m0p, m1p, reuseNonce)
    setGame({
      phase: 'challenge',
      b,
      rHex: bytesToHex(challengeCiphertext.r),
      ctHex: bytesToHex(challengeCiphertext.ciphertext),
    })
  }, [prfOracle, m0Text, m1Text, reuseNonce])

  // IND-CPA game: make a guess
  const makeGuess = useCallback((guess: number) => {
    if (game.phase !== 'challenge') return

    let correct: boolean
    if (reuseNonce) {
      // In nonce-reuse mode, adversary can detect: encrypt m0 with same nonce and compare
      const m0 = new TextEncoder().encode(m0Text)
      const maxLen = Math.max(m0.length, new TextEncoder().encode(m1Text).length)
      const m0p = new Uint8Array(maxLen)
      m0p.set(m0)
      const fixedNonce = new Uint8Array(16).fill(0x42)
      const check = cpaEncrypt(prfOracle!, m0p, fixedNonce)
      const matchesM0 = game.ctHex === bytesToHex(check.ciphertext)
      // Adversary strategy: if ciphertext matches m0 encryption, guess b=0
      const adversaryGuess = matchesM0 ? 0 : 1
      correct = adversaryGuess === game.b
    } else {
      correct = guess === game.b
    }

    setRounds(prev => [...prev, { correct }])
    setGame({
      phase: 'revealed',
      b: game.b,
      guess,
      correct,
      rHex: game.rHex,
      ctHex: game.ctHex,
    })
  }, [game, reuseNonce, prfOracle, m0Text, m1Text])

  // Run nonce reuse attack
  const runAttack = useCallback(() => {
    if (!prfOracle) return
    const m0 = new TextEncoder().encode(m0Text)
    const m1 = new TextEncoder().encode(m1Text)
    const maxLen = Math.max(m0.length, m1.length)
    const m0p = new Uint8Array(maxLen)
    const m1p = new Uint8Array(maxLen)
    m0p.set(m0); m1p.set(m1)

    const result = nonceReuseAttack(prfOracle, m0p, m1p)
    setAttackResult({
      c0Hex: bytesToHex(result.c0.ciphertext),
      c1Hex: bytesToHex(result.c1.ciphertext),
      xorCtHex: bytesToHex(result.xorCiphertexts),
      xorPtHex: bytesToHex(result.xorPlaintexts),
      match: result.match,
    })
  }, [prfOracle, m0Text, m1Text])

  // Stats
  const totalRounds = rounds.length
  const correctCount = rounds.filter(r => r.correct).length
  const advantage = totalRounds > 0 ? Math.abs(2 * (correctCount / totalRounds) - 1) : 0

  return (
    <div className="poisApp">
      {/* Header */}
      <div className="topBar">
        <div className="topTitle">
          <div className="topTitleMain">PA#3 — CPA-Secure Encryption</div>
          <div className="topTitleSub">
            C = &langle;r, F_k(r) &oplus; m&rangle; &nbsp;|&nbsp; IND-CPA Game &amp; Nonce Reuse Attack
          </div>
        </div>
      </div>

      {/* Config panel */}
      <div style={{ marginTop: 14 }}>
        <div className="panel">
          <div className="panelTitle">Configuration</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <div className="fieldLabel">PRF Type</div>
              <select
                className="select"
                value={prfId}
                onChange={e => { setPrfId(e.target.value as PrfId); setRounds([]); setGame({ phase: 'input' }) }}
              >
                {PRF_OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
              </select>
            </div>
            <div className="field">
              <div className="fieldLabel">Key k (hex, 16 bytes)</div>
              <input
                className="input"
                value={keyHex}
                onChange={e => { setKeyHex(e.target.value); setRounds([]); setGame({ phase: 'input' }) }}
                placeholder="0123456789abcdef..."
              />
            </div>
            <div className="field">
              <div className="fieldLabel">Message m&#8320; (plaintext)</div>
              <input
                className="input"
                value={m0Text}
                onChange={e => { setM0Text(e.target.value); setGame({ phase: 'input' }) }}
                placeholder="Hello, World!!!"
              />
            </div>
            <div className="field">
              <div className="fieldLabel">Message m&#8321; (plaintext)</div>
              <input
                className="input"
                value={m1Text}
                onChange={e => { setM1Text(e.target.value); setGame({ phase: 'input' }) }}
                placeholder="Goodbye World!!"
              />
            </div>
          </div>
          {!prfOracle && (
            <div style={{ color: '#ef4444', fontSize: 13, marginTop: 8 }}>
              Invalid key — must be at least 16 hex bytes (32 hex chars)
            </div>
          )}
        </div>
      </div>

      {/* Main two-column area */}
      <div className="mainArea">
        {/* Left: Encrypt/Decrypt demo */}
        <div className="panel">
          <div className="panelTitle">Encrypt &amp; Decrypt</div>
          <div className="traceList">
            <div className="traceStep">
              <div className="traceHeader">
                <span className="traceFn">Enc(k, m&#8320;)</span>
                <span className="traceBadge traceBadgeOk">PA#3</span>
              </div>
              {encDemo ? (
                <>
                  <div className="traceKV">
                    <span className="traceKey">r</span>
                    <span className="traceVal mono">{encDemo.rHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">ct</span>
                    <span className="traceVal mono">{encDemo.ctHex}</span>
                  </div>
                </>
              ) : (
                <div className="traceNote">Enter a valid key to see output</div>
              )}
            </div>

            <div className="traceStep">
              <div className="traceHeader">
                <span className="traceFn">Dec(k, r, ct)</span>
                <span className={`traceBadge ${encDemo?.ok ? 'traceBadgeOk' : ''}`}>
                  {encDemo?.ok ? 'Roundtrip OK' : '...'}
                </span>
              </div>
              {encDemo ? (
                <>
                  <div className="traceKV">
                    <span className="traceKey">hex</span>
                    <span className="traceVal mono">{encDemo.decHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">text</span>
                    <span className="traceVal">{encDemo.decText}</span>
                  </div>
                </>
              ) : (
                <div className="traceNote">—</div>
              )}
            </div>
          </div>

          {/* Nonce Reuse Attack */}
          <div className="traceBlockHeader" style={{ marginTop: 18 }}>
            Nonce Reuse Attack Demo
          </div>
          <button
            onClick={runAttack}
            disabled={!prfOracle}
            style={{
              appearance: 'none', border: '1px solid var(--border)', borderRadius: 10,
              padding: '8px 16px', background: 'var(--surface-2)', color: 'var(--text-h)',
              fontFamily: 'inherit', fontSize: 13, fontWeight: 600, cursor: 'pointer',
              marginBottom: 10,
            }}
          >
            Run Nonce Reuse Attack
          </button>
          {attackResult && (
            <div className="traceList">
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">Same nonce r = 0x424242...</span>
                  <span className="traceBadge" style={{ color: '#ef4444' }}>BROKEN</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">C&#8320;</span>
                  <span className="traceVal mono">{attackResult.c0Hex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">C&#8321;</span>
                  <span className="traceVal mono">{attackResult.c1Hex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">C&#8320;&#8853;C&#8321;</span>
                  <span className="traceVal mono">{attackResult.xorCtHex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">m&#8320;&#8853;m&#8321;</span>
                  <span className="traceVal mono">{attackResult.xorPtHex}</span>
                </div>
                <div className="traceNote" style={{ color: attackResult.match ? '#22c55e' : '#ef4444' }}>
                  {attackResult.match
                    ? 'C0 XOR C1 = m0 XOR m1 — nonce reuse leaks plaintext XOR!'
                    : 'Mismatch (unexpected)'}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right: IND-CPA Game */}
        <div className="panel">
          <div className="panelTitle">IND-CPA Security Game</div>

          {/* Reuse nonce toggle */}
          <div className="field inline" style={{ marginBottom: 14 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={reuseNonce}
                onChange={e => { setReuseNonce(e.target.checked); setRounds([]); setGame({ phase: 'input' }) }}
                style={{ width: 16, height: 16, accentColor: reuseNonce ? '#ef4444' : 'var(--accent)' }}
              />
              <span className="fieldLabel" style={{ marginBottom: 0, color: reuseNonce ? '#ef4444' : 'var(--text-h)' }}>
                {reuseNonce ? 'Reuse Nonce (BROKEN)' : 'Fresh Random Nonce (Secure)'}
              </span>
            </label>
          </div>

          {/* Game flow */}
          <div className="traceList">
            {/* Step 1: Encrypt */}
            <div className="traceStep">
              <div className="traceHeader">
                <span className="traceFn">Step 1: Challenge</span>
                <span className="traceBadge">
                  {game.phase === 'input' ? 'Ready' : game.phase === 'challenge' ? 'Guess now!' : 'Done'}
                </span>
              </div>
              <div className="traceNote">
                Challenger picks random b &#8712; &#123;0,1&#125;, encrypts m_b
              </div>
              <button
                onClick={() => { startChallenge() }}
                disabled={!prfOracle || game.phase === 'challenge'}
                style={{
                  appearance: 'none', border: '1px solid var(--border)', borderRadius: 10,
                  padding: '8px 16px', background: 'var(--accent-bg)', color: 'var(--text-h)',
                  fontFamily: 'inherit', fontSize: 13, fontWeight: 600, cursor: 'pointer',
                  marginTop: 8,
                }}
              >
                {game.phase === 'input' || game.phase === 'revealed' ? 'Encrypt (New Round)' : 'Waiting for guess...'}
              </button>
            </div>

            {/* Step 2: Show ciphertext */}
            {(game.phase === 'challenge' || game.phase === 'revealed') && (
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">Challenge Ciphertext C*</span>
                  <span className="traceBadge traceBadgeOk">
                    C* = Enc_k(m_b)
                  </span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">r</span>
                  <span className="traceVal mono">{game.rHex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">ct</span>
                  <span className="traceVal mono">{game.ctHex}</span>
                </div>
              </div>
            )}

            {/* Step 3: Guess buttons */}
            {game.phase === 'challenge' && (
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">Step 2: Your Guess</span>
                </div>
                <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                  <button
                    onClick={() => makeGuess(0)}
                    style={{
                      flex: 1, appearance: 'none', border: '1px solid var(--border)', borderRadius: 10,
                      padding: '10px', background: 'var(--surface-2)', color: 'var(--text-h)',
                      fontFamily: 'inherit', fontSize: 14, fontWeight: 700, cursor: 'pointer',
                    }}
                  >
                    Guess b = 0 (m&#8320;)
                  </button>
                  <button
                    onClick={() => makeGuess(1)}
                    style={{
                      flex: 1, appearance: 'none', border: '1px solid var(--border)', borderRadius: 10,
                      padding: '10px', background: 'var(--surface-2)', color: 'var(--text-h)',
                      fontFamily: 'inherit', fontSize: 14, fontWeight: 700, cursor: 'pointer',
                    }}
                  >
                    Guess b = 1 (m&#8321;)
                  </button>
                </div>
              </div>
            )}

            {/* Result */}
            {game.phase === 'revealed' && (
              <div className="traceStep" style={{
                borderColor: game.correct ? 'rgba(34,197,94,0.4)' : 'rgba(239,68,68,0.4)',
                background: game.correct ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)',
              }}>
                <div className="traceHeader">
                  <span className="traceFn">
                    {game.correct ? 'Correct!' : 'Wrong!'}
                  </span>
                  <span className="traceBadge" style={{ color: game.correct ? '#22c55e' : '#ef4444' }}>
                    b was {game.b}, you guessed {game.guess}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Stats */}
          <div className="traceBlockHeader" style={{ marginTop: 18 }}>
            Running Statistics ({totalRounds} round{totalRounds !== 1 ? 's' : ''})
          </div>
          <div className="outputBox">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, textAlign: 'center' }}>
              <div>
                <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-h)' }}>
                  {correctCount}/{totalRounds}
                </div>
                <div style={{ fontSize: 11, opacity: 0.7 }}>Correct</div>
              </div>
              <div>
                <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-h)' }}>
                  {totalRounds > 0 ? (correctCount / totalRounds * 100).toFixed(1) : '—'}%
                </div>
                <div style={{ fontSize: 11, opacity: 0.7 }}>Win Rate</div>
              </div>
              <div>
                <div style={{
                  fontSize: 22, fontWeight: 800,
                  color: advantage > 0.3 ? '#ef4444' : advantage > 0.15 ? '#f59e0b' : '#22c55e',
                }}>
                  {totalRounds > 0 ? advantage.toFixed(3) : '—'}
                </div>
                <div style={{ fontSize: 11, opacity: 0.7 }}>Advantage</div>
              </div>
            </div>
            {/* Progress bar */}
            {totalRounds > 0 && (
              <div style={{
                marginTop: 10, height: 6, borderRadius: 3, background: 'var(--surface-2)',
                overflow: 'hidden',
              }}>
                <div style={{
                  height: '100%', borderRadius: 3,
                  width: `${(correctCount / totalRounds) * 100}%`,
                  background: advantage > 0.3 ? '#ef4444' : '#22c55e',
                  transition: 'width 0.2s',
                }} />
              </div>
            )}
            <div style={{ fontSize: 12, marginTop: 8, opacity: 0.75 }}>
              {reuseNonce
                ? 'With nonce reuse, advantage should approach 1.0 (adversary always wins)'
                : 'With fresh nonces, advantage should converge to ~0 (no better than random guessing)'}
            </div>
            {totalRounds > 0 && (
              <button
                onClick={() => { setRounds([]); setGame({ phase: 'input' }) }}
                style={{
                  appearance: 'none', border: '1px solid var(--border)', borderRadius: 8,
                  padding: '5px 12px', background: 'transparent', color: 'var(--text-h)',
                  fontFamily: 'inherit', fontSize: 12, cursor: 'pointer', marginTop: 8, opacity: 0.7,
                }}
              >
                Reset Stats
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Proof summary */}
      <details className="proofPanel">
        <summary className="proofSummary">
          Reduction Chain &amp; Security Proof (click to expand)
        </summary>
        <div className="proofBody">
          <div className="proofStep">
            <div className="proofStepMain">
              PRF F_k &rarr; CPA-Secure Encryption (PA#3)
            </div>
            <div className="proofStepSub">
              <strong>Construction:</strong> C = &langle;r, F_k(r) &oplus; m&rangle; where r is sampled
              fresh and uniformly at random for each encryption.
            </div>
            <div className="proofStepSub">
              <strong>Theorem (PRF &rArr; CPA):</strong> If F_k is a secure PRF, then the above
              encryption scheme is CPA-secure. Specifically, for any PPT adversary A playing
              the IND-CPA game with q queries:
              Adv_CPA(A) &le; 2 &middot; Adv_PRF(B) + q&sup2;/2^n
            </div>
            <div className="proofStepSub">
              <strong>Proof sketch:</strong> Replace F_k(r) with truly random f(r). Since r is fresh
              each time, f(r) is an independent uniform random block — the ciphertext is a OTP.
              The distinguishing gap is bounded by PRF advantage.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">
              Why Nonce Reuse Breaks CPA Security
            </div>
            <div className="proofStepSub">
              If r is reused, F_k(r) is the same pad for both encryptions:
              C&#8320; = F_k(r) &oplus; m&#8320;, C&#8321; = F_k(r) &oplus; m&#8321;.
              Then C&#8320; &oplus; C&#8321; = m&#8320; &oplus; m&#8321; — the adversary learns the
              XOR of plaintexts, completely breaking IND-CPA.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">
              Full Lineage
            </div>
            <div className="proofStepSub">
              Foundation (AES/DLP) &rarr; OWF (PA#1) &rarr; PRG (PA#1, HILL) &rarr; PRF (PA#2, GGM) &rarr; CPA-Enc (PA#3)
            </div>
          </div>
        </div>
      </details>
    </div>
  )
}
