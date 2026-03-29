/**
 * PA6 Demo: CCA-Secure Symmetric Encryption via Encrypt-then-MAC
 *
 * Two-column layout comparing CPA-only (malleable) vs CCA (Encrypt-then-MAC).
 * Bottom: IND-CCA2 game + proof panel.
 */

import { useState, useMemo, useCallback } from 'react'
import {
  ccaEncrypt,
  ccaDecrypt,
  cpaMalleabilityAttack,
  ccaMalleabilityBlocked,
  indCca2Challenge,
} from '../crypto/ccaEnc'
import { bytesToHex, parseFlexibleInputToBytes } from '../utils/hex'
import './poisCliqueExplorer.css'

function randomKeyHex(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return bytesToHex(bytes)
}

export default function Pa6CcaDemo() {
  const [kEHex, setKEHex] = useState('0123456789abcdef0123456789abcdef')
  const [kMHex, setKMHex] = useState('fedcba9876543210fedcba9876543210')
  const [messageText, setMessageText] = useState('Attack at dawn!!')
  const [bitIndex, setBitIndex] = useState(0)

  // IND-CCA2 game state
  const [m0Text, setM0Text] = useState('Hello, World!!!')
  const [m1Text, setM1Text] = useState('Goodbye World!!')
  type Cca2Game =
    | { phase: 'input' }
    | { phase: 'challenge'; b: number; rHex: string; ctHex: string; tagHex: string }
    | { phase: 'revealed'; b: number; guess: number; correct: boolean; rHex: string; ctHex: string; tagHex: string }
  const [game, setGame] = useState<Cca2Game>({ phase: 'input' })
  const [rounds, setRounds] = useState<{ correct: boolean }[]>([])

  // Parse keys
  const kE = useMemo(() => {
    try {
      const b = parseFlexibleInputToBytes(kEHex)
      return b.length >= 16 ? b.slice(0, 16) : null
    } catch { return null }
  }, [kEHex])

  const kM = useMemo(() => {
    try {
      const b = parseFlexibleInputToBytes(kMHex)
      return b.length >= 16 ? b.slice(0, 16) : null
    } catch { return null }
  }, [kMHex])

  const keysValid = kE !== null && kM !== null
  const keysSame = keysValid && kEHex.trim() === kMHex.trim()

  // CPA malleability demo
  const cpaDemo = useMemo(() => {
    if (!kE) return null
    try {
      const msg = new TextEncoder().encode(messageText)
      const result = cpaMalleabilityAttack(kE, msg, bitIndex)
      return {
        rHex: bytesToHex(result.r),
        origCtHex: bytesToHex(result.originalCiphertext),
        modCtHex: bytesToHex(result.modifiedCiphertext),
        origPtText: messageText,
        modPtHex: bytesToHex(result.decryptedModified),
        modPtText: (() => {
          try { return new TextDecoder().decode(result.decryptedModified) } catch { return '(non-UTF8)' }
        })(),
        bitFlipped: result.bitFlipped,
      }
    } catch { return null }
  }, [kE, messageText, bitIndex])

  // CCA blocked demo
  const ccaDemo = useMemo(() => {
    if (!kE || !kM) return null
    try {
      const msg = new TextEncoder().encode(messageText)
      const result = ccaMalleabilityBlocked(kE, kM, msg, bitIndex)
      return {
        rHex: bytesToHex(result.r),
        origCtHex: bytesToHex(result.originalCiphertext),
        tagHex: bytesToHex(result.tag),
        modCtHex: bytesToHex(result.modifiedCiphertext),
        rejected: result.decryptResult === null,
        bitFlipped: result.bitFlipped,
      }
    } catch { return null }
  }, [kE, kM, messageText, bitIndex])

  // Basic encrypt/decrypt roundtrip
  const roundtrip = useMemo(() => {
    if (!kE || !kM) return null
    try {
      const msg = new TextEncoder().encode(messageText)
      const enc = ccaEncrypt(kE, kM, msg)
      const dec = ccaDecrypt(kE, kM, enc.r, enc.ciphertext, enc.tag)
      if (!dec) return null
      return {
        rHex: bytesToHex(enc.r),
        ctHex: bytesToHex(enc.ciphertext),
        tagHex: bytesToHex(enc.tag),
        decText: new TextDecoder().decode(dec),
        ok: new TextDecoder().decode(dec) === messageText,
      }
    } catch { return null }
  }, [kE, kM, messageText])

  // IND-CCA2 game
  const startCca2Challenge = useCallback(() => {
    if (!kE || !kM) return
    const m0 = new TextEncoder().encode(m0Text)
    const m1 = new TextEncoder().encode(m1Text)
    const maxLen = Math.max(m0.length, m1.length)
    const m0p = new Uint8Array(maxLen); m0p.set(m0)
    const m1p = new Uint8Array(maxLen); m1p.set(m1)

    const { b, challengeCiphertext } = indCca2Challenge(kE, kM, m0p, m1p)
    setGame({
      phase: 'challenge',
      b,
      rHex: bytesToHex(challengeCiphertext.r),
      ctHex: bytesToHex(challengeCiphertext.ciphertext),
      tagHex: bytesToHex(challengeCiphertext.tag),
    })
  }, [kE, kM, m0Text, m1Text])

  const makeCca2Guess = useCallback((guess: number) => {
    if (game.phase !== 'challenge') return
    const correct = guess === game.b
    setRounds(prev => [...prev, { correct }])
    setGame({
      phase: 'revealed',
      b: game.b,
      guess,
      correct,
      rHex: game.rHex,
      ctHex: game.ctHex,
      tagHex: game.tagHex,
    })
  }, [game])

  const totalRounds = rounds.length
  const correctCount = rounds.filter(r => r.correct).length
  const advantage = totalRounds > 0 ? Math.abs(2 * (correctCount / totalRounds) - 1) : 0

  return (
    <div className="poisApp">
      {/* Header */}
      <div className="topBar">
        <div className="topTitle">
          <div className="topTitleMain">PA#6 — CCA-Secure Encryption (Encrypt-then-MAC)</div>
          <div className="topTitleSub">
            CCA = CPA-Enc + CBC-MAC &nbsp;|&nbsp; Key Separation: k_E, k_M
          </div>
        </div>
      </div>

      {/* Config panel */}
      <div style={{ marginTop: 14 }}>
        <div className="panel">
          <div className="panelTitle">Configuration</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <div className="fieldLabel">Encryption Key k_E (hex, 16 bytes)</div>
              <div style={{ display: 'flex', gap: 6 }}>
                <input
                  className="input"
                  value={kEHex}
                  onChange={e => setKEHex(e.target.value)}
                  placeholder="0123456789abcdef..."
                  style={{ flex: 1 }}
                />
                <button
                  onClick={() => setKEHex(randomKeyHex())}
                  style={{
                    appearance: 'none', border: '1px solid var(--border)', borderRadius: 8,
                    padding: '4px 10px', background: 'var(--surface-2)', color: 'var(--text-h)',
                    fontFamily: 'inherit', fontSize: 12, cursor: 'pointer',
                  }}
                >
                  Random
                </button>
              </div>
            </div>
            <div className="field">
              <div className="fieldLabel">MAC Key k_M (hex, 16 bytes)</div>
              <div style={{ display: 'flex', gap: 6 }}>
                <input
                  className="input"
                  value={kMHex}
                  onChange={e => setKMHex(e.target.value)}
                  placeholder="fedcba9876543210..."
                  style={{ flex: 1 }}
                />
                <button
                  onClick={() => setKMHex(randomKeyHex())}
                  style={{
                    appearance: 'none', border: '1px solid var(--border)', borderRadius: 8,
                    padding: '4px 10px', background: 'var(--surface-2)', color: 'var(--text-h)',
                    fontFamily: 'inherit', fontSize: 12, cursor: 'pointer',
                  }}
                >
                  Random
                </button>
              </div>
            </div>
            <div className="field">
              <div className="fieldLabel">Message (plaintext)</div>
              <input
                className="input"
                value={messageText}
                onChange={e => setMessageText(e.target.value)}
                placeholder="Attack at dawn!!"
              />
            </div>
            <div className="field">
              <div className="fieldLabel">Bit index to flip in ciphertext</div>
              <input
                className="input"
                type="number"
                min={0}
                max={127}
                value={bitIndex}
                onChange={e => setBitIndex(Number(e.target.value))}
              />
            </div>
          </div>
          {!keysValid && (
            <div style={{ color: '#ef4444', fontSize: 13, marginTop: 8 }}>
              Both keys must be at least 16 hex bytes (32 hex chars)
            </div>
          )}
          {keysSame && (
            <div style={{ color: '#f59e0b', fontSize: 13, marginTop: 8 }}>
              Warning: k_E and k_M are the same. Key separation requires independent keys.
            </div>
          )}
        </div>
      </div>

      {/* Roundtrip demo */}
      {roundtrip && (
        <div style={{ marginTop: 14 }}>
          <div className="panel">
            <div className="panelTitle">Encrypt-then-MAC Roundtrip</div>
            <div className="traceList">
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">ccaEncrypt(k_E, k_M, m)</span>
                  <span className="traceBadge traceBadgeOk">PA#6</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">r</span>
                  <span className="traceVal mono">{roundtrip.rHex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">ct</span>
                  <span className="traceVal mono">{roundtrip.ctHex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">tag</span>
                  <span className="traceVal mono">{roundtrip.tagHex}</span>
                </div>
              </div>
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">ccaDecrypt(k_E, k_M, r, ct, tag)</span>
                  <span className={`traceBadge ${roundtrip.ok ? 'traceBadgeOk' : ''}`}>
                    {roundtrip.ok ? 'Roundtrip OK' : 'Mismatch'}
                  </span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">text</span>
                  <span className="traceVal">{roundtrip.decText}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main two-column: CPA malleable vs CCA blocked */}
      <div className="mainArea">
        {/* Left: CPA-Only (Malleable) */}
        <div className="panel">
          <div className="panelTitle">CPA-Only (Malleable)</div>
          <div style={{
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)',
            borderRadius: 8, padding: '8px 12px', marginBottom: 12, fontSize: 13, color: '#ef4444',
            fontWeight: 600,
          }}>
            CPA encryption is malleable — adversary can modify plaintext without the key
          </div>
          <div className="traceList">
            <div className="traceStep">
              <div className="traceHeader">
                <span className="traceFn">CPA Encrypt</span>
                <span className="traceBadge" style={{ color: '#ef4444' }}>No integrity</span>
              </div>
              {cpaDemo ? (
                <>
                  <div className="traceKV">
                    <span className="traceKey">r</span>
                    <span className="traceVal mono">{cpaDemo.rHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">ct</span>
                    <span className="traceVal mono">{cpaDemo.origCtHex}</span>
                  </div>
                </>
              ) : (
                <div className="traceNote">Enter valid keys</div>
              )}
            </div>

            {cpaDemo && (
              <>
                <div className="traceStep">
                  <div className="traceHeader">
                    <span className="traceFn">Flip bit {cpaDemo.bitFlipped} in ciphertext</span>
                    <span className="traceBadge" style={{ color: '#f59e0b' }}>Tampered</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">ct'</span>
                    <span className="traceVal mono">{cpaDemo.modCtHex}</span>
                  </div>
                </div>

                <div className="traceStep" style={{
                  borderColor: 'rgba(239,68,68,0.4)',
                  background: 'rgba(239,68,68,0.06)',
                }}>
                  <div className="traceHeader">
                    <span className="traceFn">Decrypt modified ct'</span>
                    <span className="traceBadge" style={{ color: '#ef4444' }}>Bit flipped in plaintext!</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">orig</span>
                    <span className="traceVal">{cpaDemo.origPtText}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">mod hex</span>
                    <span className="traceVal mono">{cpaDemo.modPtHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">mod text</span>
                    <span className="traceVal">{cpaDemo.modPtText}</span>
                  </div>
                  <div className="traceNote" style={{ color: '#ef4444' }}>
                    Decryption succeeded with tampered ciphertext — no integrity protection!
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right: CCA (Encrypt-then-MAC) */}
        <div className="panel">
          <div className="panelTitle">CCA (Encrypt-then-MAC)</div>
          <div style={{
            background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.3)',
            borderRadius: 8, padding: '8px 12px', marginBottom: 12, fontSize: 13, color: '#22c55e',
            fontWeight: 600,
          }}>
            MAC detects tampering — decryption rejected
          </div>
          <div className="traceList">
            <div className="traceStep">
              <div className="traceHeader">
                <span className="traceFn">CCA Encrypt</span>
                <span className="traceBadge traceBadgeOk">Authenticated</span>
              </div>
              {ccaDemo ? (
                <>
                  <div className="traceKV">
                    <span className="traceKey">r</span>
                    <span className="traceVal mono">{ccaDemo.rHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">ct</span>
                    <span className="traceVal mono">{ccaDemo.origCtHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">tag</span>
                    <span className="traceVal mono">{ccaDemo.tagHex}</span>
                  </div>
                </>
              ) : (
                <div className="traceNote">Enter valid keys</div>
              )}
            </div>

            {ccaDemo && (
              <>
                <div className="traceStep">
                  <div className="traceHeader">
                    <span className="traceFn">Flip bit {ccaDemo.bitFlipped} in ciphertext</span>
                    <span className="traceBadge" style={{ color: '#f59e0b' }}>Tampered</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">ct'</span>
                    <span className="traceVal mono">{ccaDemo.modCtHex}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey">tag</span>
                    <span className="traceVal mono">{ccaDemo.tagHex} (unchanged)</span>
                  </div>
                </div>

                <div className="traceStep" style={{
                  borderColor: ccaDemo.rejected ? 'rgba(34,197,94,0.4)' : 'rgba(239,68,68,0.4)',
                  background: ccaDemo.rejected ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)',
                }}>
                  <div className="traceHeader">
                    <span className="traceFn">Decrypt modified ct'</span>
                    <span className="traceBadge" style={{ color: ccaDemo.rejected ? '#22c55e' : '#ef4444' }}>
                      {ccaDemo.rejected ? 'REJECTED (null)' : 'Accepted (unexpected!)'}
                    </span>
                  </div>
                  <div className="traceNote" style={{ color: ccaDemo.rejected ? '#22c55e' : '#ef4444' }}>
                    {ccaDemo.rejected
                      ? 'MAC verification failed — tampered ciphertext rejected. Integrity preserved!'
                      : 'MAC verification passed unexpectedly (should not happen).'}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* IND-CCA2 Game */}
      <div style={{ marginTop: 14 }}>
        <div className="panel">
          <div className="panelTitle">IND-CCA2 Security Game</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
            <div className="field">
              <div className="fieldLabel">Message m&#8320;</div>
              <input
                className="input"
                value={m0Text}
                onChange={e => { setM0Text(e.target.value); setGame({ phase: 'input' }) }}
              />
            </div>
            <div className="field">
              <div className="fieldLabel">Message m&#8321;</div>
              <input
                className="input"
                value={m1Text}
                onChange={e => { setM1Text(e.target.value); setGame({ phase: 'input' }) }}
              />
            </div>
          </div>

          <div className="traceList">
            <div className="traceStep">
              <div className="traceHeader">
                <span className="traceFn">Step 1: Challenge</span>
                <span className="traceBadge">
                  {game.phase === 'input' ? 'Ready' : game.phase === 'challenge' ? 'Guess now!' : 'Done'}
                </span>
              </div>
              <div className="traceNote">
                Challenger picks random b, encrypts m_b with Encrypt-then-MAC. Adversary gets a decryption oracle (rejects challenge ciphertext).
              </div>
              <button
                onClick={startCca2Challenge}
                disabled={!keysValid || game.phase === 'challenge'}
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

            {(game.phase === 'challenge' || game.phase === 'revealed') && (
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">Challenge Ciphertext C*</span>
                  <span className="traceBadge traceBadgeOk">C* = CCA-Enc(m_b)</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">r</span>
                  <span className="traceVal mono">{game.rHex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">ct</span>
                  <span className="traceVal mono">{game.ctHex}</span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">tag</span>
                  <span className="traceVal mono">{game.tagHex}</span>
                </div>
              </div>
            )}

            {game.phase === 'challenge' && (
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">Step 2: Your Guess</span>
                </div>
                <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                  <button
                    onClick={() => makeCca2Guess(0)}
                    style={{
                      flex: 1, appearance: 'none', border: '1px solid var(--border)', borderRadius: 10,
                      padding: '10px', background: 'var(--surface-2)', color: 'var(--text-h)',
                      fontFamily: 'inherit', fontSize: 14, fontWeight: 700, cursor: 'pointer',
                    }}
                  >
                    Guess b = 0 (m&#8320;)
                  </button>
                  <button
                    onClick={() => makeCca2Guess(1)}
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
              CCA2 security: advantage should converge to ~0 (no better than random guessing)
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

      {/* Proof panel */}
      <details className="proofPanel">
        <summary className="proofSummary">
          Security Proof &amp; Reduction Chain (click to expand)
        </summary>
        <div className="proofBody">
          <div className="proofStep">
            <div className="proofStepMain">
              CPA + EUF-CMA MAC &rarr; CCA2 Security (PA#6)
            </div>
            <div className="proofStepSub">
              <strong>Theorem (Encrypt-then-MAC):</strong> If (Enc, Dec) is CPA-secure and (Mac, Vrfy) is
              EUF-CMA secure, then the Encrypt-then-MAC composition is CCA2-secure.
            </div>
            <div className="proofStepSub">
              <strong>Proof sketch:</strong> Any CCA2 adversary must either (1) forge a valid MAC tag
              on a new ciphertext (contradicting EUF-CMA security), or (2) distinguish encryptions
              without the decryption oracle (contradicting CPA security). Since the MAC covers the
              full ciphertext (r || ct), any modification is detected.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">
              Why Encrypt-then-MAC, not MAC-then-Encrypt?
            </div>
            <div className="proofStepSub">
              <strong>Encrypt-then-MAC:</strong> MAC is computed over the ciphertext. The receiver
              checks the MAC before decrypting. This provides CCA2 security generically.
            </div>
            <div className="proofStepSub">
              <strong>MAC-then-Encrypt:</strong> MAC is computed over the plaintext, then both are
              encrypted. The receiver must decrypt before verifying, which can leak information
              through padding oracles (e.g., TLS 1.0 BEAST/POODLE attacks). Not generically CCA-secure.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">
              Key Separation: Why k_E &ne; k_M
            </div>
            <div className="proofStepSub">
              Using the same key for encryption and MAC breaks the security proof. The reduction
              to CPA security needs to simulate MAC queries, and the reduction to EUF-CMA needs
              to simulate encryption queries. Neither is possible with a shared key, since the
              simulator does not know the key. Independent keys allow modular security proofs.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">
              Malleability: CPA allows bit flips, MAC prevents them
            </div>
            <div className="proofStepSub">
              CPA encryption (counter mode) is XOR-based: flipping bit i in ciphertext flips
              bit i in the plaintext. This is a <em>chosen-ciphertext attack</em>. With Encrypt-then-MAC,
              any ciphertext modification invalidates the MAC tag, and decryption returns null.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">
              Full Lineage
            </div>
            <div className="proofStepSub">
              AES &rarr; OWF (PA#1) &rarr; PRG (PA#1) &rarr; PRF (PA#2) &rarr; CPA-Enc (PA#3) + MAC (PA#5) &rarr; CCA-Enc (PA#6)
            </div>
          </div>
        </div>
      </details>
    </div>
  )
}
