/**
 * PA5 Demo: Message Authentication Codes (MACs)
 *
 * Left panel  — MAC Tagger: compute and verify PRF-MAC / CBC-MAC tags.
 * Right panel — EUF-CMA Forgery Game: try to forge a valid tag on a new message.
 * Bottom      — Proof panel with reduction lineage.
 */

import { useState, useMemo, useCallback, useRef } from 'react'
import {
  buildPRF,
  prfMac,
  cbcMac,
  prfMacVerify,
  cbcMacVerify,
  createEufCmaGame,
  makePRFFromMAC,
} from '../crypto/mac'
import { runDistinguishingGame } from '../crypto/prf'
import { bytesToHex, hexToBytes } from '../utils/hex'
import './poisCliqueExplorer.css'

type PrfType = 'aes' | 'ggm'
type MacType = 'prf-mac' | 'cbc-mac'

interface SignedEntry {
  index: number
  messageHex: string
  tagHex: string
}

const DEFAULT_KEY_HEX = '000102030405060708090a0b0c0d0e0f'

export default function Pa5MacDemo() {
  // ── Shared state ────────────────────────────────────────────────────────
  const [prfType, setPrfType] = useState<PrfType>('aes')
  const [keyHex, setKeyHex] = useState(DEFAULT_KEY_HEX)
  const [macType, setMacType] = useState<MacType>('prf-mac')

  // ── Left panel state ────────────────────────────────────────────────────
  const [messageText, setMessageText] = useState('hello world')
  const [tagOutput, setTagOutput] = useState('')
  const [verifyMsg, setVerifyMsg] = useState('')
  const [verifyTag, setVerifyTag] = useState('')
  const [verifyResult, setVerifyResult] = useState<'valid' | 'invalid' | ''>('')

  // ── Right panel state ───────────────────────────────────────────────────
  const [signedPairs, setSignedPairs] = useState<SignedEntry[]>([])
  const [forgeryMsg, setForgeryMsg] = useState('')
  const [forgeryTag, setForgeryTag] = useState('')
  const [forgeryResult, setForgeryResult] = useState('')
  const [attempts, setAttempts] = useState(0)
  const [successes, setSuccesses] = useState(0)
  const gameRef = useRef<ReturnType<typeof createEufCmaGame> | null>(null)

  // ── Bottom panel state ──────────────────────────────────────────────────
  const [macPrfResult, setMacPrfResult] = useState('')

  // ── Build PRF oracle from key ───────────────────────────────────────────
  const prf = useMemo(() => {
    try {
      const kb = hexToBytes(keyHex)
      if (kb.length < 16) {
        const padded = new Uint8Array(16)
        padded.set(kb)
        return buildPRF(prfType, padded)
      }
      return buildPRF(prfType, kb)
    } catch {
      return null
    }
  }, [prfType, keyHex])

  // ── Left: Compute tag ───────────────────────────────────────────────────
  const handleComputeTag = useCallback(() => {
    if (!prf) return
    try {
      const msgBytes = new TextEncoder().encode(messageText)
      const tag = macType === 'prf-mac' ? prfMac(prf, msgBytes) : cbcMac(prf, msgBytes)
      setTagOutput(bytesToHex(tag))
    } catch (e) {
      setTagOutput(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }, [prf, messageText, macType])

  // ── Left: Verify tag ───────────────────────────────────────────────────
  const handleVerify = useCallback(() => {
    if (!prf) return
    try {
      const msgBytes = new TextEncoder().encode(verifyMsg)
      const tagBytes = hexToBytes(verifyTag)
      const ok = macType === 'prf-mac'
        ? prfMacVerify(prf, msgBytes, tagBytes)
        : cbcMacVerify(prf, msgBytes, tagBytes)
      setVerifyResult(ok ? 'valid' : 'invalid')
    } catch {
      setVerifyResult('invalid')
    }
  }, [prf, verifyMsg, verifyTag, macType])

  // ── Right: Generate signed pairs ───────────────────────────────────────
  const handleGeneratePairs = useCallback(() => {
    if (!prf) return
    const game = createEufCmaGame(prf, macType)
    gameRef.current = game
    const pairs: SignedEntry[] = []
    for (let i = 0; i < 50; i++) {
      const msg = new Uint8Array(16)
      // Deterministic but varied messages
      msg[0] = (i >> 8) & 0xff
      msg[1] = i & 0xff
      msg[2] = 0xaa
      const tag = game.sign(msg)
      pairs.push({
        index: i,
        messageHex: bytesToHex(msg),
        tagHex: bytesToHex(tag),
      })
    }
    setSignedPairs(pairs)
    setForgeryResult('')
    setAttempts(0)
    setSuccesses(0)
  }, [prf, macType])

  // ── Right: Submit forgery ──────────────────────────────────────────────
  const handleSubmitForgery = useCallback(() => {
    if (!gameRef.current) {
      setForgeryResult('Generate signed pairs first.')
      return
    }
    try {
      const msgBytes = hexToBytes(forgeryMsg)
      const tagBytes = hexToBytes(forgeryTag)
      const result = gameRef.current.verifyForgery(msgBytes, tagBytes)
      setAttempts((a) => a + 1)
      if (result.accepted) {
        setSuccesses((s) => s + 1)
        setForgeryResult('Accepted: ' + result.reason)
      } else {
        setForgeryResult('Rejected: ' + result.reason)
      }
    } catch (e) {
      setForgeryResult(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }, [forgeryMsg, forgeryTag])

  // ── Bottom: MAC => PRF test ────────────────────────────────────────────
  const handleMacPrfTest = useCallback(() => {
    if (!prf) return
    const macFn = macType === 'prf-mac' ? prfMac : cbcMac
    const prfFromMac = makePRFFromMAC(macFn, prf)
    const result = runDistinguishingGame(prfFromMac, 200)
    setMacPrfResult(
      `chi2 = ${result.chiSquaredStat.toFixed(2)}, p = ${result.pValue.toFixed(4)} => ${result.verdict}`
    )
  }, [prf, macType])

  return (
    <div className="poisApp">
      <div className="topBar">
        <div className="topTitle">
          <span className="topTitleMain">PA5 — Message Authentication Codes</span>
          <span className="topTitleSub">PRF-MAC, CBC-MAC, EUF-CMA forgery game</span>
        </div>
      </div>

      <div className="mainArea" style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        {/* ── Left Panel: MAC Tagger ──────────────────────────────────── */}
        <div className="panel" style={{ flex: 1, minWidth: 340 }}>
          <div className="panelTitle">MAC Tagger</div>

          <div className="field">
            <label className="fieldLabel">PRF type</label>
            <select
              className="select"
              value={prfType}
              onChange={(e) => setPrfType(e.target.value as PrfType)}
            >
              <option value="aes">AES</option>
              <option value="ggm">GGM</option>
            </select>
          </div>

          <div className="field">
            <label className="fieldLabel">Key (hex)</label>
            <input
              className="input mono"
              value={keyHex}
              onChange={(e) => setKeyHex(e.target.value)}
              spellCheck={false}
            />
          </div>

          <div className="field">
            <label className="fieldLabel">MAC type</label>
            <select
              className="select"
              value={macType}
              onChange={(e) => setMacType(e.target.value as MacType)}
            >
              <option value="prf-mac">PRF-MAC (fixed-length)</option>
              <option value="cbc-mac">CBC-MAC (variable-length)</option>
            </select>
          </div>

          <div className="field">
            <label className="fieldLabel">Message (text)</label>
            <input
              className="input"
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
            />
          </div>

          <button className="select" style={{ cursor: 'pointer', marginBottom: 8 }} onClick={handleComputeTag}>
            Compute Tag
          </button>

          {tagOutput && (
            <div className="outputBox">
              <span className="traceKey">Tag: </span>
              <span className="traceVal mono">{tagOutput}</span>
            </div>
          )}

          <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '12px 0' }} />

          <div className="panelTitle" style={{ fontSize: 13 }}>Verify</div>

          <div className="field">
            <label className="fieldLabel">Message (text)</label>
            <input
              className="input"
              value={verifyMsg}
              onChange={(e) => { setVerifyMsg(e.target.value); setVerifyResult('') }}
            />
          </div>

          <div className="field">
            <label className="fieldLabel">Tag (hex)</label>
            <input
              className="input mono"
              value={verifyTag}
              onChange={(e) => { setVerifyTag(e.target.value); setVerifyResult('') }}
              spellCheck={false}
            />
          </div>

          <button className="select" style={{ cursor: 'pointer', marginBottom: 8 }} onClick={handleVerify}>
            Verify
          </button>

          {verifyResult && (
            <div className="outputBox">
              <span className={verifyResult === 'valid' ? 'traceBadgeOk' : 'traceBadge'}>
                {verifyResult === 'valid' ? 'Valid' : 'Invalid'}
              </span>
            </div>
          )}
        </div>

        {/* ── Right Panel: EUF-CMA Forgery Game ──────────────────────── */}
        <div className="panel" style={{ flex: 1, minWidth: 340 }}>
          <div className="panelTitle">EUF-CMA Forgery Game</div>

          <button className="select" style={{ cursor: 'pointer', marginBottom: 8 }} onClick={handleGeneratePairs}>
            Generate 50 Signed Pairs
          </button>

          <div style={{ marginBottom: 8, fontSize: 13, color: 'var(--text-m)' }}>
            Attempts: {attempts} | Successes: {successes}
          </div>

          {signedPairs.length > 0 && (
            <div className="traceList" style={{ maxHeight: 220, overflowY: 'auto', marginBottom: 12 }}>
              <div className="traceBlockHeader">Signed messages (m, t)</div>
              {signedPairs.map((p) => (
                <div key={p.index} className="traceStep" style={{ fontSize: 11 }}>
                  <span className="traceKey">m{p.index}: </span>
                  <span className="traceVal mono">{p.messageHex.slice(0, 24)}...</span>
                  {' '}
                  <span className="traceKey">t: </span>
                  <span className="traceVal mono">{p.tagHex.slice(0, 24)}...</span>
                </div>
              ))}
            </div>
          )}

          <div className="field">
            <label className="fieldLabel">Forgery message m* (hex)</label>
            <input
              className="input mono"
              value={forgeryMsg}
              onChange={(e) => setForgeryMsg(e.target.value)}
              placeholder="e.g. deadbeef..."
              spellCheck={false}
            />
          </div>

          <div className="field">
            <label className="fieldLabel">Forgery tag t* (hex)</label>
            <input
              className="input mono"
              value={forgeryTag}
              onChange={(e) => setForgeryTag(e.target.value)}
              placeholder="e.g. 00112233..."
              spellCheck={false}
            />
          </div>

          <button className="select" style={{ cursor: 'pointer', marginBottom: 8 }} onClick={handleSubmitForgery}>
            Submit Forgery
          </button>

          {forgeryResult && (
            <div className="outputBox">
              <span className={forgeryResult.startsWith('Accepted') ? 'traceBadgeOk' : 'traceBadge'}>
                {forgeryResult}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom: Proof Panel ────────────────────────────────────────── */}
      <div style={{ padding: '0 18px 18px' }}>
        <details className="proofPanel">
          <summary className="proofSummary">Proof Sketch and Reduction Lineage</summary>
          <div className="proofBody">
            <div className="proofStep">
              <div className="proofStepMain">PRF =&gt; MAC (forward direction)</div>
              <div className="proofStepSub">
                Mac_k(m) = F_k(m). If an adversary can forge a valid (m*, t*) pair without
                querying m*, then it can distinguish F_k from a truly random function --
                contradicting PRF security. Security of MAC reduces directly to PRF security.
              </div>
            </div>

            <div className="proofStep">
              <div className="proofStepMain">CBC-MAC (variable-length extension)</div>
              <div className="proofStepSub">
                For fixed-length messages, CBC-MAC is a secure MAC under the PRF assumption.
                Split message into blocks M_1, ..., M_l. Set z_0 = 0, z_i = F_k(z_(i-1) XOR M_i).
                Tag = z_l. Security proof uses a hybrid argument over the chain of PRF calls.
              </div>
            </div>

            <div className="proofStep">
              <div className="proofStepMain">MAC =&gt; PRF (backward direction)</div>
              <div className="proofStepSub">
                An EUF-CMA secure MAC, when evaluated on uniformly random inputs, behaves as a PRF.
                If a distinguisher could separate MAC outputs from random, it could be used to
                construct a forgery adversary -- contradicting EUF-CMA security.
              </div>
            </div>

            <div className="proofStep">
              <div className="proofStepMain">MAC =&gt; PRF distinguishing test</div>
              <div className="proofStepSub">
                <button
                  className="select"
                  style={{ cursor: 'pointer', fontSize: 12, padding: '4px 10px' }}
                  onClick={handleMacPrfTest}
                >
                  Run MAC-as-PRF distinguishing game
                </button>
                {macPrfResult && (
                  <span style={{ marginLeft: 8, fontSize: 12 }} className="mono">{macPrfResult}</span>
                )}
              </div>
            </div>

            <div className="proofStep">
              <div className="proofStepMain">Full lineage</div>
              <div className="proofStepSub">
                Foundation &rarr; OWF &rarr; PRG (HILL) &rarr; PRF (GGM tree) &rarr; MAC (PRF-MAC / CBC-MAC)
              </div>
            </div>
          </div>
        </details>
      </div>
    </div>
  )
}
