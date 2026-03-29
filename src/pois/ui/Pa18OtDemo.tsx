/**
 * PA#18 — 1-out-of-2 Oblivious Transfer (Bellare-Micali) Demo
 *
 * Two-panel layout: Alice (Sender) | Bob (Receiver)
 * Middle: Protocol log
 * Bottom: Proof panel
 */

import { useState } from 'react'
import {
  OT_Receiver_Step1,
  OT_Sender_Step,
  OT_Receiver_Step2,
  otCorrectnessTest,
  otReceiverPrivacyDemo,
  otSenderPrivacyDemo,
  type OTReceiverState,
  type OTReceiverPrivacyResult,
  type OTSenderPrivacyResult,
  type OTCorrectnessResult,
} from '../crypto/obliviousTransfer'
import { bigintToHex } from '../crypto/elgamal'
import type { ElGamalPublicKey, ElGamalCiphertext } from '../crypto/elgamal'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Inline styles                                                      */
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
  background: 'var(--accent, #4466cc)',
  color: '#fff',
}

const monoStyle: React.CSSProperties = {
  fontFamily: '"Fira Mono", "Cascadia Code", monospace',
  fontSize: 13,
  wordBreak: 'break-all',
}

const labelStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  color: 'var(--text-dim, #888)',
  marginBottom: 4,
}

const warningStyle: React.CSSProperties = {
  background: 'rgba(220, 50, 50, 0.12)',
  border: '1px solid rgba(220, 50, 50, 0.4)',
  borderRadius: 6,
  padding: '10px 14px',
  color: '#f55',
  fontWeight: 600,
  fontSize: 13,
  marginTop: 12,
}

const successStyle: React.CSSProperties = {
  background: 'rgba(50, 180, 50, 0.12)',
  border: '1px solid rgba(50, 180, 50, 0.4)',
  borderRadius: 6,
  padding: '10px 14px',
  color: '#4c4',
  fontWeight: 600,
  fontSize: 13,
  marginTop: 12,
}

const proofPanelStyle: React.CSSProperties = {
  padding: 16,
  border: '1px solid var(--border, #444)',
  borderRadius: 8,
  background: 'var(--surface, #1e1e1e)',
  marginTop: 16,
  fontSize: 13,
  lineHeight: 1.6,
}

const logPanelStyle: React.CSSProperties = {
  padding: 16,
  border: '1px solid var(--border, #444)',
  borderRadius: 8,
  background: 'var(--surface, #1e1e1e)',
  marginTop: 16,
  fontSize: 13,
}

const inputStyle: React.CSSProperties = {
  ...monoStyle,
  width: '100%',
  padding: '4px 8px',
  border: '1px solid var(--border, #555)',
  borderRadius: 4,
  background: 'var(--bg, #111)',
  color: 'var(--text-h, #eee)',
  boxSizing: 'border-box' as const,
}

/* ------------------------------------------------------------------ */
/*  Helper: format pk for display                                      */
/* ------------------------------------------------------------------ */

function PkDisplay({ pk, label }: { pk: ElGamalPublicKey; label: string }) {
  return (
    <div style={{ marginTop: 8 }}>
      <div style={labelStyle}>{label}</div>
      <div style={monoStyle}>
        <div><b>h</b> = {bigintToHex(pk.h)}</div>
      </div>
    </div>
  )
}

function CtDisplay({ ct, label }: { ct: ElGamalCiphertext; label: string }) {
  return (
    <div style={{ marginTop: 8 }}>
      <div style={labelStyle}>{label}</div>
      <div style={monoStyle}>
        <div><b>c1</b> = {bigintToHex(ct.c1)}</div>
        <div><b>c2</b> = {bigintToHex(ct.c2)}</div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

type ProtocolStep =
  | { type: 'receiver_keys'; b: 0 | 1 }
  | { type: 'sender_encrypt'; m0: string; m1: string }
  | { type: 'receiver_decrypt'; result: bigint }
  | { type: 'cheat_attempt'; success: boolean; message: string }

export default function Pa18OtDemo() {
  // Protocol state
  const [choiceBit, setChoiceBit] = useState<0 | 1 | null>(null)
  const [m0Input, setM0Input] = useState('42')
  const [m1Input, setM1Input] = useState('99')

  // Step 1 results
  const [pk0, setPk0] = useState<ElGamalPublicKey | null>(null)
  const [pk1, setPk1] = useState<ElGamalPublicKey | null>(null)
  const [receiverState, setReceiverState] = useState<OTReceiverState | null>(null)

  // Step 2 results
  const [C0, setC0] = useState<ElGamalCiphertext | null>(null)
  const [C1, setC1] = useState<ElGamalCiphertext | null>(null)

  // Step 3 results
  const [decryptedMsg, setDecryptedMsg] = useState<bigint | null>(null)
  const [cheatResult, setCheatResult] = useState<string | null>(null)

  // Protocol log
  const [log, setLog] = useState<ProtocolStep[]>([])

  // Test results
  const [correctnessResult, setCorrectnessResult] = useState<OTCorrectnessResult | null>(null)
  const [privacyResult, setPrivacyResult] = useState<OTReceiverPrivacyResult | null>(null)
  const [senderPrivResult, setSenderPrivResult] = useState<OTSenderPrivacyResult | null>(null)

  /* ---- actions ---- */

  function handleChooseBit(b: 0 | 1) {
    // Reset everything
    setChoiceBit(b)
    setC0(null)
    setC1(null)
    setDecryptedMsg(null)
    setCheatResult(null)

    // Step 1: Receiver generates keys
    const { pk0: p0, pk1: p1, state } = OT_Receiver_Step1(b)
    setPk0(p0)
    setPk1(p1)
    setReceiverState(state)
    setLog([{ type: 'receiver_keys', b }])
  }

  function handleSenderEncrypt() {
    if (!pk0 || !pk1) return
    try {
      const m0 = BigInt(m0Input)
      const m1 = BigInt(m1Input)
      const { C0: c0, C1: c1 } = OT_Sender_Step(pk0, pk1, m0, m1)
      setC0(c0)
      setC1(c1)
      setDecryptedMsg(null)
      setCheatResult(null)
      setLog(prev => [...prev, { type: 'sender_encrypt', m0: m0Input, m1: m1Input }])
    } catch (e) {
      // ignore invalid input
    }
  }

  function handleReceiverDecrypt() {
    if (!receiverState || !C0 || !C1) return
    const result = OT_Receiver_Step2(receiverState, C0, C1)
    setDecryptedMsg(result)
    setLog(prev => [...prev, { type: 'receiver_decrypt', result }])
  }

  function handleCheatAttempt() {
    if (!receiverState || !C0 || !C1 || choiceBit === null) return
    // Try to decrypt the OTHER ciphertext using a wrong key

    // Use the receiver's sk_b to try decrypting the other ciphertext
    // This will produce garbage because sk_b does not correspond to the other pk
    try {
      const wrongDecrypt = OT_Receiver_Step2(
        { ...receiverState, b: (1 - choiceBit) as 0 | 1 },
        C0,
        C1,
      )
      const expected = choiceBit === 0 ? BigInt(m1Input) : BigInt(m0Input)
      const success = wrongDecrypt === expected
      const msg = success
        ? 'Decryption produced the correct value (should not happen with proper fake key)'
        : `Decryption produced ${wrongDecrypt.toString()} -- garbage, not the real message ${expected.toString()}`
      setCheatResult(msg)
      setLog(prev => [...prev, { type: 'cheat_attempt', success, message: msg }])
    } catch {
      setCheatResult('Decryption failed entirely -- no valid secret key for this ciphertext')
      setLog(prev => [...prev, { type: 'cheat_attempt', success: false, message: 'Decryption error' }])
    }
  }

  function handleCorrectnessTest() {
    setCorrectnessResult(otCorrectnessTest(10))
  }

  function handleReceiverPrivacy() {
    const b: 0 | 1 = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) as 0 | 1
    setPrivacyResult(otReceiverPrivacyDemo(b))
  }

  function handleSenderPrivacy() {
    setSenderPrivResult(otSenderPrivacyDemo())
  }

  /* ---- render ---- */

  return (
    <div style={{ padding: 24 }}>
      <h2 style={{ marginBottom: 16 }}>PA#18 — 1-out-of-2 Oblivious Transfer</h2>

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        {/* Left panel -- Alice (Sender) */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0 }}>Alice (Sender)</h3>

          <div style={labelStyle}>Message m0</div>
          <input
            type="text"
            value={m0Input}
            onChange={e => setM0Input(e.target.value)}
            style={inputStyle}
          />

          <div style={{ ...labelStyle, marginTop: 10 }}>Message m1</div>
          <input
            type="text"
            value={m1Input}
            onChange={e => setM1Input(e.target.value)}
            style={inputStyle}
          />

          {pk0 && pk1 && (
            <>
              <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
              <div style={labelStyle}>Received from Bob</div>
              <PkDisplay pk={pk0} label="pk0" />
              <PkDisplay pk={pk1} label="pk1" />

              <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-dim, #888)', fontStyle: 'italic' }}>
                Alice does not know which key Bob holds the secret for.
              </div>

              <div style={{ marginTop: 12 }}>
                <button
                  style={btnStyle}
                  onClick={handleSenderEncrypt}
                >
                  Encrypt m0 under pk0, m1 under pk1
                </button>
              </div>

              {C0 && C1 && (
                <>
                  <CtDisplay ct={C0} label="C0 = Enc(pk0, m0)" />
                  <CtDisplay ct={C1} label="C1 = Enc(pk1, m1)" />
                </>
              )}
            </>
          )}
        </div>

        {/* Right panel -- Bob (Receiver) */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0 }}>Bob (Receiver)</h3>

          <div style={labelStyle}>Choice bit b</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              style={choiceBit === 0 ? btnActiveStyle : btnStyle}
              onClick={() => handleChooseBit(0)}
            >
              Choose b=0
            </button>
            <button
              style={choiceBit === 1 ? btnActiveStyle : btnStyle}
              onClick={() => handleChooseBit(1)}
            >
              Choose b=1
            </button>
          </div>

          {choiceBit !== null && pk0 && pk1 && receiverState && (
            <>
              <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
              <div style={labelStyle}>Generated keys</div>
              <PkDisplay pk={pk0} label={`pk0 ${choiceBit === 0 ? '(honest -- has sk)' : '(fake -- no sk)'}`} />
              <PkDisplay pk={pk1} label={`pk1 ${choiceBit === 1 ? '(honest -- has sk)' : '(fake -- no sk)'}`} />

              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-dim, #888)' }}>
                sk_b = <span style={monoStyle}>{bigintToHex(receiverState.sk_b)}</span> (hidden from Alice)
              </div>

              {C0 && C1 && (
                <>
                  <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
                  <div style={labelStyle}>Received ciphertexts</div>
                  <CtDisplay ct={C0} label="C0" />
                  <CtDisplay ct={C1} label="C1" />

                  <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                    <button style={btnStyle} onClick={handleReceiverDecrypt}>
                      Decrypt C_{choiceBit === 0 ? '0' : '1'}
                    </button>
                    <button
                      style={{ ...btnStyle, background: 'rgba(220, 50, 50, 0.2)' }}
                      onClick={handleCheatAttempt}
                    >
                      Cheat: try C_{choiceBit === 0 ? '1' : '0'}
                    </button>
                  </div>

                  {decryptedMsg !== null && (
                    <div style={successStyle}>
                      m_{choiceBit} = {decryptedMsg.toString()}
                    </div>
                  )}

                  {cheatResult && (
                    <div style={warningStyle}>
                      {cheatResult}
                    </div>
                  )}

                  {decryptedMsg !== null && (
                    <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-dim, #888)' }}>
                      m_{1 - choiceBit} = ?? (no secret key to decrypt)
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>

      {/* Protocol Log */}
      {log.length > 0 && (
        <div style={logPanelStyle}>
          <h3 style={{ marginTop: 0, marginBottom: 8 }}>Protocol Log</h3>
          <div style={{ maxHeight: 200, overflowY: 'auto' }}>
            {log.map((step, i) => (
              <div key={i} style={{
                ...monoStyle,
                fontSize: 12,
                padding: '4px 0',
                borderBottom: '1px solid var(--border, #333)',
              }}>
                {step.type === 'receiver_keys' && (
                  <span>
                    <b>Bob -&gt; Alice:</b> Sends pk0, pk1 (choice bit b={step.b}, hidden from Alice)
                  </span>
                )}
                {step.type === 'sender_encrypt' && (
                  <span>
                    <b>Alice -&gt; Bob:</b> Sends C0=Enc(pk0, {step.m0}), C1=Enc(pk1, {step.m1})
                  </span>
                )}
                {step.type === 'receiver_decrypt' && (
                  <span>
                    <b>Bob:</b> Decrypts C_b to get m_b = {step.result.toString()}
                  </span>
                )}
                {step.type === 'cheat_attempt' && (
                  <span style={{ color: step.success ? '#4c4' : '#f55' }}>
                    <b>Bob (cheat):</b> {step.message}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tests section */}
      <div style={{ ...logPanelStyle, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <button style={btnStyle} onClick={handleCorrectnessTest}>
          Correctness Test (10 trials)
        </button>
        <button style={btnStyle} onClick={handleReceiverPrivacy}>
          Receiver Privacy Demo
        </button>
        <button style={btnStyle} onClick={handleSenderPrivacy}>
          Sender Privacy Demo
        </button>

        {correctnessResult && (
          <div style={{ width: '100%' }}>
            <div style={{
              fontWeight: 600,
              color: correctnessResult.passed ? '#4c4' : '#f44',
              marginBottom: 6,
            }}>
              Correctness: {correctnessResult.passed ? 'ALL PASSED' : 'FAILED'} ({correctnessResult.trials.length} trials)
            </div>
            <div style={{ maxHeight: 150, overflowY: 'auto' }}>
              {correctnessResult.trials.map((t, i) => (
                <div key={i} style={{ ...monoStyle, fontSize: 11, padding: '2px 0' }}>
                  Trial {i + 1}: b={t.b}, m0={t.m0.toString()}, m1={t.m1.toString()},
                  result={t.result.toString()}, expected={t.expected.toString()}{' '}
                  <span style={{ color: t.correct ? '#4c4' : '#f44' }}>
                    {t.correct ? 'OK' : 'FAIL'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {privacyResult && (
          <div style={{ width: '100%' }}>
            <div style={labelStyle}>Receiver Privacy (b={privacyResult.b})</div>
            <div style={{ ...monoStyle, fontSize: 12 }}>
              <div>pk0.h = {bigintToHex(privacyResult.pk0.h)} -- valid group element: {privacyResult.pk0IsGroupElement ? 'yes' : 'no'}</div>
              <div>pk1.h = {bigintToHex(privacyResult.pk1.h)} -- valid group element: {privacyResult.pk1IsGroupElement ? 'yes' : 'no'}</div>
              <div style={{
                marginTop: 6,
                fontWeight: 600,
                color: privacyResult.indistinguishable ? '#4c4' : '#f44',
              }}>
                {privacyResult.indistinguishable
                  ? 'Both pks are indistinguishable group elements -- sender cannot determine b'
                  : 'Distinguishable -- privacy broken'}
              </div>
            </div>
          </div>
        )}

        {senderPrivResult && (
          <div style={{ width: '100%' }}>
            <div style={labelStyle}>Sender Privacy (b={senderPrivResult.b})</div>
            <div style={{ ...monoStyle, fontSize: 12 }}>
              <div>Receiver got m_{senderPrivResult.b} = {senderPrivResult.result.toString()}</div>
              <div>Other ciphertext C_{1 - senderPrivResult.b}: c1={bigintToHex(senderPrivResult.otherCiphertext.c1)}, c2={bigintToHex(senderPrivResult.otherCiphertext.c2)}</div>
              <div>Brute-force attempts: {senderPrivResult.bruteForceAttempts}</div>
              <div style={{
                marginTop: 6,
                fontWeight: 600,
                color: senderPrivResult.bruteForceSuccess ? '#f44' : '#4c4',
              }}>
                {senderPrivResult.message}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Proof panel */}
      <div style={proofPanelStyle}>
        <h3 style={{ marginTop: 0, marginBottom: 8 }}>Bellare-Micali OT Construction</h3>

        <p>
          <b>Construction:</b> The Bellare-Micali 1-out-of-2 OT uses ElGamal encryption.
          The receiver generates two public keys: one honest (with known secret key) and
          one fake (a random group element with no known discrete log). The sender encrypts
          each message under the corresponding public key. The receiver can only decrypt the
          ciphertext encrypted under their honest key.
        </p>

        <p>
          <b>Receiver Privacy:</b> The sender sees (pk0, pk1) but cannot determine which is
          the honest key and which is the fake. Both are random elements of the group
          Z_p*, and the fake key h = g^r mod p is computationally indistinguishable from
          an honest ElGamal public key (both are just random group elements). Under DDH,
          the sender has no advantage in guessing b.
        </p>

        <p>
          <b>Sender Privacy:</b> The receiver cannot decrypt C_{'{1-b}'} because they do not
          possess the secret key for pk_{'{1-b}'}. Recovering the message would require solving
          the Discrete Logarithm Problem (DLP) to extract the secret key from the fake
          public key -- which is computationally infeasible for cryptographic parameters.
        </p>

        <p>
          <b>Lineage:</b> PA#18 (Oblivious Transfer) builds on PA#16 (ElGamal), which
          builds on PA#11 (Diffie-Hellman key exchange), which builds on PA#13 (Miller-Rabin
          primality testing for safe prime generation). The security of OT ultimately rests
          on the hardness of the Decisional Diffie-Hellman (DDH) problem.
        </p>
      </div>
    </div>
  )
}
