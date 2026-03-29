/**
 * PA#19 — Secure AND Gate Demo
 *
 * Two-panel layout: Alice | Bob
 * Middle: Protocol step log
 * Bottom: Truth table, XOR demo, proof panel
 */

import { useState } from 'react'
import {
  secureAND,
  secureXOR,
  secureNOT,
  truthTableTest,
  privacyCheck,
  type Bit,
  type SecureANDResult,
  type SecureXORResult,
  type TruthTableResult,
  type PrivacyCheckResult,
} from '../crypto/secureGates'
import { bigintToHex } from '../crypto/elgamal'
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

const logPanelStyle: React.CSSProperties = {
  padding: 16,
  border: '1px solid var(--border, #444)',
  borderRadius: 8,
  background: 'var(--surface, #1e1e1e)',
  marginTop: 16,
  fontSize: 13,
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

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

type ProtocolStep =
  | { type: 'bob_keys' }
  | { type: 'alice_encrypt'; m0: number; m1: number }
  | { type: 'bob_decrypt'; result: number }

export default function Pa19SecureAndDemo() {
  /* -- input state -- */
  const [aliceBit, setAliceBit] = useState<Bit | null>(null)
  const [bobBit, setBobBit] = useState<Bit | null>(null)

  /* -- AND result -- */
  const [andResult, setAndResult] = useState<SecureANDResult | null>(null)
  const [protocolLog, setProtocolLog] = useState<ProtocolStep[]>([])

  /* -- XOR result -- */
  const [xorResult, setXorResult] = useState<SecureXORResult | null>(null)

  /* -- NOT result -- */
  const [notResult, setNotResult] = useState<{ input: Bit; result: number } | null>(null)

  /* -- truth table -- */
  const [truthTable, setTruthTable] = useState<TruthTableResult | null>(null)

  /* -- privacy -- */
  const [privResult, setPrivResult] = useState<PrivacyCheckResult | null>(null)

  /* ---- actions ---- */

  function handleRunAND() {
    if (aliceBit === null || bobBit === null) return
    const res = secureAND(aliceBit, bobBit)
    setAndResult(res)
    setProtocolLog([
      { type: 'bob_keys' },
      { type: 'alice_encrypt', m0: 0, m1: aliceBit },
      { type: 'bob_decrypt', result: res.result },
    ])
  }

  function handleRunXOR() {
    if (aliceBit === null || bobBit === null) return
    setXorResult(secureXOR(aliceBit, bobBit))
  }

  function handleRunNOT() {
    if (aliceBit === null) return
    const res = secureNOT(aliceBit)
    setNotResult({ input: aliceBit, result: res.result })
  }

  function handleTruthTable() {
    setTruthTable(truthTableTest(10))
  }

  function handlePrivacy() {
    if (aliceBit === null || bobBit === null) return
    setPrivResult(privacyCheck(aliceBit, bobBit))
  }

  /* ---- render ---- */

  return (
    <div style={{ padding: 24 }}>
      <h2 style={{ marginBottom: 16 }}>PA#19 — Secure AND, XOR, and NOT Gates</h2>

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        {/* Left panel -- Alice */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0 }}>Alice (OT Sender)</h3>

          <div style={labelStyle}>Input bit a</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              style={aliceBit === 0 ? btnActiveStyle : btnStyle}
              onClick={() => { setAliceBit(0); setAndResult(null); setProtocolLog([]) }}
            >
              a = 0
            </button>
            <button
              style={aliceBit === 1 ? btnActiveStyle : btnStyle}
              onClick={() => { setAliceBit(1); setAndResult(null); setProtocolLog([]) }}
            >
              a = 1
            </button>
          </div>

          {aliceBit !== null && (
            <>
              <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
              <div style={labelStyle}>Alice's OT messages</div>
              <div style={monoStyle}>
                <div>m0 = 0 (if Bob picks b=0, he gets 0)</div>
                <div>m1 = {aliceBit} (if Bob picks b=1, he gets a={aliceBit})</div>
              </div>
              <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-dim, #888)', fontStyle: 'italic' }}>
                Alice knows a={aliceBit} but not b. OT hides Bob's choice.
              </div>

              {andResult && (
                <>
                  <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
                  <div style={labelStyle}>Ciphertexts sent</div>
                  <div style={monoStyle}>
                    <div><b>C0</b> = Enc(pk0, 0)</div>
                    <div style={{ fontSize: 11 }}>c1 = {bigintToHex(andResult.otTranscript.C0.c1)}</div>
                    <div style={{ fontSize: 11 }}>c2 = {bigintToHex(andResult.otTranscript.C0.c2)}</div>
                    <div style={{ marginTop: 6 }}><b>C1</b> = Enc(pk1, {aliceBit})</div>
                    <div style={{ fontSize: 11 }}>c1 = {bigintToHex(andResult.otTranscript.C1.c1)}</div>
                    <div style={{ fontSize: 11 }}>c2 = {bigintToHex(andResult.otTranscript.C1.c2)}</div>
                  </div>
                </>
              )}
            </>
          )}
        </div>

        {/* Right panel -- Bob */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0 }}>Bob (OT Receiver)</h3>

          <div style={labelStyle}>Input bit b</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              style={bobBit === 0 ? btnActiveStyle : btnStyle}
              onClick={() => { setBobBit(0); setAndResult(null); setProtocolLog([]) }}
            >
              b = 0
            </button>
            <button
              style={bobBit === 1 ? btnActiveStyle : btnStyle}
              onClick={() => { setBobBit(1); setAndResult(null); setProtocolLog([]) }}
            >
              b = 1
            </button>
          </div>

          {bobBit !== null && (
            <>
              <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
              <div style={labelStyle}>Bob's OT choice</div>
              <div style={monoStyle}>
                <div>Choice bit b = {bobBit}</div>
              </div>
              <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-dim, #888)', fontStyle: 'italic' }}>
                Bob knows b={bobBit} but not a. OT hides Alice's messages.
              </div>

              {andResult && (
                <>
                  <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />
                  <div style={labelStyle}>Bob's received value</div>
                  <div style={monoStyle}>
                    m_b = m_{bobBit} = {andResult.result}
                  </div>
                  <div style={successStyle}>
                    a AND b = {aliceBit} AND {bobBit} = {andResult.result}
                  </div>
                  <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-dim, #888)' }}>
                    Bob knows b and a AND b but not a (cannot distinguish Alice's bit from the output alone
                    {bobBit === 0 ? ' -- output is always 0 when b=0' : ''}).
                  </div>
                </>
              )}
            </>
          )}
        </div>
      </div>

      {/* Run buttons */}
      <div style={{ ...logPanelStyle, display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <button
          style={btnStyle}
          onClick={handleRunAND}
          disabled={aliceBit === null || bobBit === null}
        >
          Run Secure AND
        </button>
        <button
          style={btnStyle}
          onClick={handleRunXOR}
          disabled={aliceBit === null || bobBit === null}
        >
          Run Secure XOR
        </button>
        <button
          style={btnStyle}
          onClick={handleRunNOT}
          disabled={aliceBit === null}
        >
          Run Secure NOT(a)
        </button>

        {xorResult && aliceBit !== null && bobBit !== null && (
          <div style={{ width: '100%', marginTop: 4 }}>
            <div style={labelStyle}>XOR Result (secret sharing)</div>
            <div style={monoStyle}>
              a XOR b = {aliceBit} XOR {bobBit} = {xorResult.result}
            </div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text-dim, #888)', marginTop: 4 }}>
              Alice's share = {xorResult.shares.alice}, Bob's share = {xorResult.shares.bob},
              output = {xorResult.shares.alice} XOR {xorResult.shares.bob} = {xorResult.result}
            </div>
          </div>
        )}

        {notResult && (
          <div style={{ width: '100%', marginTop: 4 }}>
            <div style={labelStyle}>NOT Result (local flip)</div>
            <div style={monoStyle}>
              NOT {notResult.input} = {notResult.result}
            </div>
          </div>
        )}
      </div>

      {/* Protocol step log */}
      {protocolLog.length > 0 && (
        <div style={logPanelStyle}>
          <h3 style={{ marginTop: 0, marginBottom: 8 }}>Protocol Step Log</h3>
          <div style={{ maxHeight: 200, overflowY: 'auto' }}>
            {protocolLog.map((step, i) => (
              <div key={i} style={{
                ...monoStyle,
                fontSize: 12,
                padding: '4px 0',
                borderBottom: '1px solid var(--border, #333)',
              }}>
                {step.type === 'bob_keys' && (
                  <span>
                    <b>Step 1 -- Bob generates keys:</b> Bob picks choice bit b={bobBit},
                    generates honest key pk_{bobBit} (has sk) and fake key pk_{bobBit === 0 ? 1 : 0} (no sk).
                    Sends pk0, pk1 to Alice.
                  </span>
                )}
                {step.type === 'alice_encrypt' && (
                  <span>
                    <b>Step 2 -- Alice encrypts:</b> Alice encrypts (m0={step.m0}, m1={step.m1})
                    under (pk0, pk1). Sends C0, C1 to Bob.
                  </span>
                )}
                {step.type === 'bob_decrypt' && (
                  <span>
                    <b>Step 3 -- Bob decrypts C_b:</b> Bob decrypts C_{bobBit} using sk_{bobBit}
                    {' -> '} gets m_{bobBit} = {step.result} = a AND b.
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Truth table section */}
      <div style={{ ...logPanelStyle, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <button style={btnStyle} onClick={handleTruthTable}>
          Run All 4 Combinations (10x each)
        </button>
        <button
          style={btnStyle}
          onClick={handlePrivacy}
          disabled={aliceBit === null || bobBit === null}
        >
          Privacy Verification
        </button>

        {truthTable && (
          <div style={{ width: '100%' }}>
            <div style={{
              fontWeight: 600,
              color: truthTable.passed ? '#4c4' : '#f44',
              marginBottom: 8,
            }}>
              Truth Table: {truthTable.passed ? 'ALL PASSED' : 'FAILED'} ({truthTable.entries.length} trials)
            </div>
            <table style={{
              width: '100%',
              borderCollapse: 'collapse',
              ...monoStyle,
              fontSize: 11,
            }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border, #555)' }}>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>a</th>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>b</th>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>AND</th>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>Expected</th>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>XOR</th>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>Expected</th>
                  <th style={{ padding: '4px 8px', textAlign: 'left' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {truthTable.entries.map((e, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border, #333)' }}>
                    <td style={{ padding: '3px 8px' }}>{e.a}</td>
                    <td style={{ padding: '3px 8px' }}>{e.b}</td>
                    <td style={{ padding: '3px 8px' }}>{e.andResult}</td>
                    <td style={{ padding: '3px 8px' }}>{e.andExpected}</td>
                    <td style={{ padding: '3px 8px' }}>{e.xorResult}</td>
                    <td style={{ padding: '3px 8px' }}>{e.xorExpected}</td>
                    <td style={{
                      padding: '3px 8px',
                      color: (e.andCorrect && e.xorCorrect) ? '#4c4' : '#f44',
                    }}>
                      {(e.andCorrect && e.xorCorrect) ? 'OK' : 'FAIL'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {privResult && (
          <div style={{ width: '100%', marginTop: 8 }}>
            <div style={labelStyle}>Privacy Verification (a={privResult.a}, b={privResult.b})</div>
            <div style={{ marginTop: 8 }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Bob's view:</div>
              <div style={{ ...monoStyle, fontSize: 12 }}>
                <div>Choice bit: b={privResult.bobView.choiceBit}</div>
                <div>Received value: m_b = {privResult.bobView.receivedValue.toString()}</div>
                <div style={{
                  marginTop: 4,
                  color: privResult.bobView.canDetermineA ? '#f44' : '#4c4',
                  fontWeight: 600,
                }}>
                  Can determine a: {privResult.bobView.canDetermineA ? 'YES (privacy broken!)' : 'NO'}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-dim, #888)', marginTop: 2 }}>
                  {privResult.bobView.explanation}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 12 }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Alice's view:</div>
              <div style={{ ...monoStyle, fontSize: 12 }}>
                <div>Sent messages: m0={privResult.aliceView.sentMessages.m0.toString()}, m1={privResult.aliceView.sentMessages.m1.toString()}</div>
                <div style={{
                  marginTop: 4,
                  color: privResult.aliceView.canDetermineB ? '#f44' : '#4c4',
                  fontWeight: 600,
                }}>
                  Can determine b: {privResult.aliceView.canDetermineB ? 'YES (privacy broken!)' : 'NO'}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-dim, #888)', marginTop: 2 }}>
                  {privResult.aliceView.explanation}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Proof panel */}
      <div style={proofPanelStyle}>
        <h3 style={{ marginTop: 0, marginBottom: 8 }}>Secure Gate Constructions</h3>

        <p>
          <b>Secure AND from OT:</b> Alice sets OT messages (m0=0, m1=a). Bob uses choice bit b.
          If b=0, Bob receives m0=0 (since 0 AND a = 0 for all a). If b=1, Bob receives m1=a
          (since 1 AND a = a). Thus m_b = a AND b. Alice does not learn b (OT receiver privacy),
          and Bob does not learn a beyond what a AND b reveals (OT sender privacy).
        </p>

        <p>
          <b>Secure XOR from Secret Sharing (Free):</b> Alice samples random r in {'{0,1}'},
          computes her share s_A = a XOR r, and sends r to Bob. Bob computes his share s_B = b XOR r.
          The output is s_A XOR s_B = (a XOR r) XOR (b XOR r) = a XOR b. This requires only
          one round of communication with no cryptographic operations -- it is a "free" gate.
        </p>

        <p>
          <b>Secure NOT (Local Flip, Free):</b> NOT a = 1 - a. Alice computes this locally with
          no communication whatsoever. NOT is the simplest secure gate -- it requires neither OT
          nor secret sharing.
        </p>

        <p>
          <b>Privacy Argument:</b> In the AND gate, OT guarantees: (1) Alice cannot determine b
          because both public keys pk0 and pk1 are computationally indistinguishable under the DDH
          assumption, and (2) Bob cannot determine a beyond what the output reveals because he
          cannot decrypt the ciphertext encrypted under the fake public key (DLP hardness).
        </p>

        <p>
          <b>Lineage:</b> PA#19 (Secure Gates) builds on PA#18 (Oblivious Transfer), which builds
          on PA#16 (ElGamal), PA#11 (Diffie-Hellman), and PA#13 (Miller-Rabin). The AND gate
          makes a single OT call; XOR and NOT are free.
        </p>
      </div>
    </div>
  )
}
