/**
 * PA#4 Demo: Block Cipher Modes of Operation (CBC / OFB / CTR)
 */

import { useState, useMemo, useCallback } from 'react'
import {
  cbcEncrypt, cbcDecrypt,
  ofbEncrypt, ofbDecrypt,
  ctrEncrypt, ctrDecrypt,
  cbcIvReuseAttack,
  ofbKeystreamReuseAttack,
  type CbcBlockStep,
  type OfbBlockStep,
  type CtrBlockStep,
} from '../crypto/blockModes'
import { bytesToHex, hexToBytes } from '../utils/hex'
import './poisCliqueExplorer.css'

const BLOCK_SIZE = 16

function safeHexToBytes(hex: string, len: number): Uint8Array | null {
  try {
    const b = hexToBytes(hex)
    return b.length === len ? b : null
  } catch {
    return null
  }
}

function toHex(arr: Uint8Array): string {
  return bytesToHex(arr)
}

function truncHex(hex: string, max = 32): string {
  if (hex.length <= max) return hex
  return hex.slice(0, max / 2) + '...' + hex.slice(-max / 2)
}

type ModeTab = 'CBC' | 'OFB' | 'CTR'

export default function Pa4ModesDemo() {
  const [mode, setMode] = useState<ModeTab>('CBC')
  const [keyHex, setKeyHex] = useState('0123456789abcdef0123456789abcdef')
  const [ivHex, setIvHex] = useState('000102030405060708090a0b0c0d0e0f')
  const [msgText, setMsgText] = useState('Hello, AES modes of operation!')

  // Attack inputs
  const [atkM1, setAtkM1] = useState('Attack message 1')
  const [atkM2, setAtkM2] = useState('Attack message 2')
  // Messages sharing first block for CBC demo
  const [cbcAtkM1, setCbcAtkM1] = useState('SameFirstBlock!!Different tail')
  const [cbcAtkM2, setCbcAtkM2] = useState('SameFirstBlock!!Another tail!!')

  const keyBytes = useMemo(() => safeHexToBytes(keyHex, 16), [keyHex])
  const ivBytes = useMemo(() => safeHexToBytes(ivHex, 16), [ivHex])

  // ─── Encrypt / Decrypt demo ────────────────────────────────────────────────

  const encResult = useMemo(() => {
    if (!keyBytes) return null
    const msg = new TextEncoder().encode(msgText)
    if (msg.length === 0) return null

    try {
      if (mode === 'CBC') {
        if (!ivBytes) return null
        const enc = cbcEncrypt(keyBytes, ivBytes, msg)
        const ct = enc.output.slice(BLOCK_SIZE) // strip IV
        const dec = cbcDecrypt(keyBytes, ivBytes, ct)
        const decText = new TextDecoder().decode(dec.output)
        return { enc, dec, ct, decText, ok: decText === msgText, encSteps: enc.steps, decSteps: dec.steps }
      } else if (mode === 'OFB') {
        if (!ivBytes) return null
        const enc = ofbEncrypt(keyBytes, ivBytes, msg)
        const ct = enc.output.slice(BLOCK_SIZE)
        const dec = ofbDecrypt(keyBytes, ivBytes, ct)
        // For OFB decrypt, the output includes IV prefix; strip it
        const decBody = dec.output.slice(BLOCK_SIZE)
        const decText = new TextDecoder().decode(decBody)
        return { enc, dec, ct, decText, ok: decText === msgText, encSteps: enc.steps, decSteps: dec.steps }
      } else {
        // CTR
        const enc = ctrEncrypt(keyBytes, msg)
        const nonce = enc.nonce
        const ct = enc.output.slice(BLOCK_SIZE)
        const dec = ctrDecrypt(keyBytes, nonce, ct)
        const decText = new TextDecoder().decode(dec.output)
        return { enc, dec, ct, decText, ok: decText === msgText, encSteps: enc.steps, decSteps: dec.steps, nonce }
      }
    } catch {
      return null
    }
  }, [keyBytes, ivBytes, msgText, mode])

  // ─── CBC IV Reuse Attack ───────────────────────────────────────────────────

  const cbcAttack = useMemo(() => {
    if (!keyBytes || !ivBytes || mode !== 'CBC') return null
    try {
      const m1 = new TextEncoder().encode(cbcAtkM1)
      const m2 = new TextEncoder().encode(cbcAtkM2)
      return cbcIvReuseAttack(keyBytes, ivBytes, m1, m2)
    } catch {
      return null
    }
  }, [keyBytes, ivBytes, cbcAtkM1, cbcAtkM2, mode])

  // ─── OFB Keystream Reuse Attack ───────────────────────────────────────────

  const ofbAttack = useMemo(() => {
    if (!keyBytes || !ivBytes || mode !== 'OFB') return null
    try {
      const m1 = new TextEncoder().encode(atkM1)
      const m2 = new TextEncoder().encode(atkM2)
      return ofbKeystreamReuseAttack(keyBytes, ivBytes, m1, m2)
    } catch {
      return null
    }
  }, [keyBytes, ivBytes, atkM1, atkM2, mode])

  // ─── CTR random nonce demo ────────────────────────────────────────────────

  const [ctrDemo, setCtrDemo] = useState<{
    c1Hex: string; c2Hex: string; n1Hex: string; n2Hex: string; different: boolean
  } | null>(null)

  const runCtrDemo = useCallback(() => {
    if (!keyBytes) return
    const m = new TextEncoder().encode(atkM1)
    const e1 = ctrEncrypt(keyBytes, m)
    const e2 = ctrEncrypt(keyBytes, m)
    setCtrDemo({
      c1Hex: toHex(e1.output),
      c2Hex: toHex(e2.output),
      n1Hex: toHex(e1.nonce),
      n2Hex: toHex(e2.nonce),
      different: toHex(e1.output) !== toHex(e2.output),
    })
  }, [keyBytes, atkM1])

  // ─── Render helpers ────────────────────────────────────────────────────────

  const renderCbcSteps = (steps: CbcBlockStep[], label: string) => (
    <div className="traceList">
      {steps.map(s => (
        <div key={s.blockIndex} className="traceStep">
          <div className="traceHeader">
            <span className="traceFn">{label} Block {s.blockIndex}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">In</span>
            <span className="traceVal mono">{truncHex(toHex(s.plainBlock))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">XOR</span>
            <span className="traceVal mono">{truncHex(toHex(s.xorWithPrev))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Out</span>
            <span className="traceVal mono">{truncHex(toHex(s.cipherBlock))}</span>
          </div>
        </div>
      ))}
    </div>
  )

  const renderOfbSteps = (steps: OfbBlockStep[]) => (
    <div className="traceList">
      {steps.map(s => (
        <div key={s.blockIndex} className="traceStep">
          <div className="traceHeader">
            <span className="traceFn">Block {s.blockIndex}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Keystream</span>
            <span className="traceVal mono">{truncHex(toHex(s.keystreamBlock))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Input</span>
            <span className="traceVal mono">{truncHex(toHex(s.inputBlock))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Output</span>
            <span className="traceVal mono">{truncHex(toHex(s.outputBlock))}</span>
          </div>
        </div>
      ))}
    </div>
  )

  const renderCtrSteps = (steps: CtrBlockStep[]) => (
    <div className="traceList">
      {steps.map(s => (
        <div key={s.blockIndex} className="traceStep">
          <div className="traceHeader">
            <span className="traceFn">Block {s.blockIndex}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Ctr</span>
            <span className="traceVal mono">{truncHex(toHex(s.counterValue))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Keystream</span>
            <span className="traceVal mono">{truncHex(toHex(s.keystreamBlock))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Input</span>
            <span className="traceVal mono">{truncHex(toHex(s.inputBlock))}</span>
          </div>
          <div className="traceKV">
            <span className="traceKey">Output</span>
            <span className="traceVal mono">{truncHex(toHex(s.outputBlock))}</span>
          </div>
        </div>
      ))}
    </div>
  )

  return (
    <div className="poisApp">
      {/* Header */}
      <div className="topBar">
        <div className="topTitle">
          <div className="topTitleMain">PA#4 — Modes of Operation</div>
          <div className="topTitleSub">
            CBC / OFB / CTR using AES-128 &nbsp;|&nbsp; IV-Reuse &amp; Keystream-Reuse Attacks
          </div>
        </div>
      </div>

      {/* Mode selector tabs */}
      <div style={{
        display: 'flex', gap: 4, padding: '12px 18px 0',
      }}>
        {(['CBC', 'OFB', 'CTR'] as ModeTab[]).map(m => (
          <button
            key={m}
            onClick={() => setMode(m)}
            style={{
              appearance: 'none', border: '1px solid var(--border)',
              background: mode === m ? 'var(--accent-bg)' : 'var(--surface)',
              color: 'var(--text-h)', fontFamily: 'inherit', fontWeight: mode === m ? 700 : 500,
              fontSize: 14, padding: '8px 20px', borderRadius: '8px 8px 0 0', cursor: 'pointer',
              borderBottom: mode === m ? '2px solid var(--accent)' : '2px solid transparent',
              opacity: mode === m ? 1 : 0.65,
            }}
          >
            {m}
          </button>
        ))}
      </div>

      {/* Config panel */}
      <div style={{ marginTop: 4 }}>
        <div className="panel">
          <div className="panelTitle">Configuration</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <div className="fieldLabel">Key k (hex, 16 bytes)</div>
              <input className="input" value={keyHex}
                onChange={e => setKeyHex(e.target.value)}
                placeholder="0123456789abcdef..." />
              {!keyBytes && <div style={{ color: '#ef4444', fontSize: 12, marginTop: 4 }}>Must be exactly 32 hex chars (16 bytes)</div>}
            </div>
            {mode !== 'CTR' ? (
              <div className="field">
                <div className="fieldLabel">IV (hex, 16 bytes)</div>
                <input className="input" value={ivHex}
                  onChange={e => setIvHex(e.target.value)}
                  placeholder="000102030405060708090a0b0c0d0e0f" />
                {!ivBytes && <div style={{ color: '#ef4444', fontSize: 12, marginTop: 4 }}>Must be exactly 32 hex chars (16 bytes)</div>}
              </div>
            ) : (
              <div className="field">
                <div className="fieldLabel">Nonce (auto-generated)</div>
                <input className="input" disabled value="Random nonce sampled per encryption"
                  style={{ opacity: 0.5 }} />
              </div>
            )}
            <div className="field" style={{ gridColumn: '1 / -1' }}>
              <div className="fieldLabel">Message (plaintext text)</div>
              <input className="input" value={msgText}
                onChange={e => setMsgText(e.target.value)}
                placeholder="Hello, AES modes of operation!" />
            </div>
          </div>
        </div>
      </div>

      {/* Main two-column area */}
      <div className="mainArea">
        {/* Left: Encrypt & Decrypt */}
        <div className="panel">
          <div className="panelTitle">Encrypt &amp; Decrypt</div>

          {encResult ? (
            <>
              {/* Encryption steps */}
              <div className="traceBlockHeader">Encryption Steps</div>
              {mode === 'CTR' && encResult.nonce && (
                <div className="traceKV" style={{ marginBottom: 6 }}>
                  <span className="traceKey">Nonce</span>
                  <span className="traceVal mono">{toHex(encResult.nonce)}</span>
                </div>
              )}
              {mode === 'CBC' && renderCbcSteps(encResult.encSteps as CbcBlockStep[], 'Enc')}
              {mode === 'OFB' && renderOfbSteps(encResult.encSteps as OfbBlockStep[])}
              {mode === 'CTR' && renderCtrSteps(encResult.encSteps as CtrBlockStep[])}

              <div className="traceKV" style={{ marginTop: 8 }}>
                <span className="traceKey">Ciphertext</span>
                <span className="traceVal mono" style={{ wordBreak: 'break-all' }}>{toHex(encResult.ct)}</span>
              </div>

              {/* Decryption result */}
              <div className="traceBlockHeader" style={{ marginTop: 14 }}>Decryption</div>
              <div className="traceStep">
                <div className="traceHeader">
                  <span className="traceFn">Roundtrip</span>
                  <span className={`traceBadge ${encResult.ok ? 'traceBadgeOk' : ''}`}>
                    {encResult.ok ? 'Dec(k, Enc(k, m)) = m' : 'MISMATCH'}
                  </span>
                </div>
                <div className="traceKV">
                  <span className="traceKey">Recovered</span>
                  <span className="traceVal">{encResult.decText}</span>
                </div>
              </div>
            </>
          ) : (
            <div className="traceNote">Enter a valid key{mode !== 'CTR' ? ' and IV' : ''} to see output</div>
          )}
        </div>

        {/* Right: Attack Demos */}
        <div className="panel">
          <div className="panelTitle">Attack Demos</div>

          {mode === 'CBC' && (
            <>
              <div className="traceBlockHeader">CBC IV-Reuse Attack</div>
              <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 8 }}>
                Two messages encrypted with the same key and IV.
                If the first plaintext blocks are equal, the first ciphertext blocks are equal.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
                <div className="field">
                  <div className="fieldLabel">M1</div>
                  <input className="input" value={cbcAtkM1}
                    onChange={e => setCbcAtkM1(e.target.value)} />
                </div>
                <div className="field">
                  <div className="fieldLabel">M2</div>
                  <input className="input" value={cbcAtkM2}
                    onChange={e => setCbcAtkM2(e.target.value)} />
                </div>
              </div>

              {cbcAttack && (
                <div className="traceList">
                  <div className="traceStep">
                    <div className="traceHeader">
                      <span className="traceFn">Plaintext Block 0</span>
                      <span className="traceBadge" style={{
                        color: cbcAttack.plaintextFirstBlocksMatch ? '#f59e0b' : '#22c55e'
                      }}>
                        {cbcAttack.plaintextFirstBlocksMatch ? 'EQUAL' : 'Different'}
                      </span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">M1[0]</span>
                      <span className="traceVal mono">{cbcAttack.m1Block0Hex}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">M2[0]</span>
                      <span className="traceVal mono">{cbcAttack.m2Block0Hex}</span>
                    </div>
                  </div>
                  <div className="traceStep" style={{
                    borderColor: cbcAttack.firstBlocksMatch ? 'rgba(239,68,68,0.5)' : 'rgba(34,197,94,0.4)',
                    background: cbcAttack.firstBlocksMatch ? 'rgba(239,68,68,0.06)' : 'transparent',
                  }}>
                    <div className="traceHeader">
                      <span className="traceFn">Ciphertext Block 0</span>
                      <span className="traceBadge" style={{
                        color: cbcAttack.firstBlocksMatch ? '#ef4444' : '#22c55e'
                      }}>
                        {cbcAttack.firstBlocksMatch ? 'EQUAL — IV reuse leaks block equality!' : 'Different'}
                      </span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">C1[0]</span>
                      <span className="traceVal mono">{cbcAttack.c1Block0Hex}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">C2[0]</span>
                      <span className="traceVal mono">{cbcAttack.c2Block0Hex}</span>
                    </div>
                    {cbcAttack.firstBlocksMatch && (
                      <div style={{ color: '#ef4444', fontSize: 12, fontWeight: 700, marginTop: 6 }}>
                        WARNING: Reusing IV in CBC mode leaks whether plaintext blocks are equal!
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}

          {mode === 'OFB' && (
            <>
              <div className="traceBlockHeader">OFB Keystream-Reuse Attack</div>
              <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 8 }}>
                Two messages encrypted with the same key + IV produce the same keystream.
                XORing the ciphertexts yields the XOR of the plaintexts.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
                <div className="field">
                  <div className="fieldLabel">M1</div>
                  <input className="input" value={atkM1}
                    onChange={e => setAtkM1(e.target.value)} />
                </div>
                <div className="field">
                  <div className="fieldLabel">M2</div>
                  <input className="input" value={atkM2}
                    onChange={e => setAtkM2(e.target.value)} />
                </div>
              </div>

              {ofbAttack && (
                <div className="traceList">
                  <div className="traceStep" style={{
                    borderColor: ofbAttack.match ? 'rgba(239,68,68,0.5)' : 'rgba(34,197,94,0.4)',
                    background: ofbAttack.match ? 'rgba(239,68,68,0.06)' : 'transparent',
                  }}>
                    <div className="traceHeader">
                      <span className="traceFn">Keystream Reuse</span>
                      <span className="traceBadge" style={{ color: ofbAttack.match ? '#ef4444' : '#22c55e' }}>
                        {ofbAttack.match ? 'C1 XOR C2 = M1 XOR M2' : 'Mismatch'}
                      </span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">C1 xor C2</span>
                      <span className="traceVal mono" style={{ wordBreak: 'break-all' }}>{toHex(ofbAttack.xorCiphertexts)}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">M1 xor M2</span>
                      <span className="traceVal mono" style={{ wordBreak: 'break-all' }}>{toHex(ofbAttack.xorPlaintexts)}</span>
                    </div>
                    {ofbAttack.match && (
                      <div style={{ color: '#ef4444', fontSize: 12, fontWeight: 700, marginTop: 6 }}>
                        WARNING: Keystream reuse in OFB is equivalent to OTP reuse -- plaintext XOR is exposed!
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}

          {mode === 'CTR' && (
            <>
              <div className="traceBlockHeader">CTR: Random Nonce Prevents Reuse</div>
              <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 8 }}>
                Each CTR encryption samples a fresh random nonce, so encrypting the same
                message twice produces completely different ciphertexts.
              </div>
              <div className="field" style={{ marginBottom: 10 }}>
                <div className="fieldLabel">Message for demo</div>
                <input className="input" value={atkM1}
                  onChange={e => setAtkM1(e.target.value)} />
              </div>
              <button
                onClick={runCtrDemo}
                disabled={!keyBytes}
                style={{
                  appearance: 'none', border: '1px solid var(--border)', borderRadius: 10,
                  padding: '8px 16px', background: 'var(--surface-2)', color: 'var(--text-h)',
                  fontFamily: 'inherit', fontSize: 13, fontWeight: 600, cursor: 'pointer',
                  marginBottom: 10,
                }}
              >
                Encrypt Twice with Random Nonces
              </button>

              {ctrDemo && (
                <div className="traceList">
                  <div className="traceStep" style={{
                    borderColor: ctrDemo.different ? 'rgba(34,197,94,0.4)' : 'rgba(239,68,68,0.5)',
                    background: ctrDemo.different ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)',
                  }}>
                    <div className="traceHeader">
                      <span className="traceFn">Two Encryptions</span>
                      <span className="traceBadge" style={{ color: ctrDemo.different ? '#22c55e' : '#ef4444' }}>
                        {ctrDemo.different ? 'Different ciphertexts (SECURE)' : 'Same ciphertext (BAD)'}
                      </span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">Nonce 1</span>
                      <span className="traceVal mono">{ctrDemo.n1Hex}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">C1</span>
                      <span className="traceVal mono" style={{ wordBreak: 'break-all' }}>{truncHex(ctrDemo.c1Hex, 64)}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">Nonce 2</span>
                      <span className="traceVal mono">{ctrDemo.n2Hex}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey">C2</span>
                      <span className="traceVal mono" style={{ wordBreak: 'break-all' }}>{truncHex(ctrDemo.c2Hex, 64)}</span>
                    </div>
                    <div style={{ color: '#22c55e', fontSize: 12, fontWeight: 600, marginTop: 6 }}>
                      Random nonces ensure distinct ciphertexts even for identical plaintexts.
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Proof / comparison panel */}
      <details className="proofPanel">
        <summary className="proofSummary">
          Mode Comparison &amp; Security Properties (click to expand)
        </summary>
        <div className="proofBody">
          <div className="proofStep">
            <div className="proofStepMain">CBC (Cipher Block Chaining)</div>
            <div className="proofStepSub">
              <strong>Encryption:</strong> C_i = AES_k(M_i XOR C_(i-1)), C_0 = IV. Sequential encryption, parallel decryption.
            </div>
            <div className="proofStepSub">
              <strong>IV Reuse:</strong> If the same IV is used for two messages, matching plaintext blocks produce matching
              ciphertext blocks -- leaking block equality to an eavesdropper.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">OFB (Output Feedback)</div>
            <div className="proofStepSub">
              <strong>Keystream:</strong> O_i = AES_k(O_(i-1)), O_0 = IV. Pre-computable (no dependency on plaintext).
              Acts as a stream cipher: C_i = M_i XOR O_i.
            </div>
            <div className="proofStepSub">
              <strong>Keystream Reuse:</strong> Same key + IV produces same keystream.
              C1 XOR C2 = M1 XOR M2 -- equivalent to one-time pad reuse.
            </div>
          </div>
          <div className="proofStep">
            <div className="proofStepMain">CTR (Counter Mode, Randomized)</div>
            <div className="proofStepSub">
              <strong>Keystream:</strong> Block i = AES_k(nonce + i). Fully parallelizable for both encryption
              and decryption. No feedback between blocks.
            </div>
            <div className="proofStepSub">
              <strong>Nonce:</strong> A fresh random nonce per encryption ensures distinct keystreams.
              Nonce reuse would break security identically to OFB keystream reuse.
            </div>
          </div>

          {/* Comparison table */}
          <div className="proofStep">
            <div className="proofStepMain">Comparison Table</div>
            <table style={{
              width: '100%', borderCollapse: 'collapse', fontSize: 13, marginTop: 6,
            }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ textAlign: 'left', padding: '6px 8px' }}>Property</th>
                  <th style={{ textAlign: 'center', padding: '6px 8px' }}>CBC</th>
                  <th style={{ textAlign: 'center', padding: '6px 8px' }}>OFB</th>
                  <th style={{ textAlign: 'center', padding: '6px 8px' }}>CTR</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}>Parallel Encrypt</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>Yes</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}>Parallel Decrypt</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>Yes</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>Yes</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}>Needs AES Decrypt</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>Yes</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}>Error Propagation</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>1-2 blocks</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>1 bit</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>1 bit</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}>Padding Required</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>Yes (PKCS#7)</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>No</td>
                </tr>
                <tr>
                  <td style={{ padding: '6px 8px' }}>IV/Nonce Sensitivity</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>Leaks block eq.</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>OTP reuse</td>
                  <td style={{ textAlign: 'center', padding: '6px 8px' }}>OTP reuse</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="proofStep">
            <div className="proofStepMain">Full Lineage</div>
            <div className="proofStepSub">
              Foundation (AES) &rarr; OWF (PA#1) &rarr; PRG (PA#1) &rarr; PRF (PA#2, GGM) &rarr; CPA-Enc (PA#3) &rarr; Block Cipher Modes (PA#4)
            </div>
          </div>
        </div>
      </details>
    </div>
  )
}
