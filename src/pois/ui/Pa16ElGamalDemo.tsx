/**
 * PA#16 — ElGamal Public-Key Cryptosystem Demo
 *
 * Left panel:  Key generation, encryption, decryption with roundtrip verification.
 * Right panel: Malleability attack — multiply c2 by 2, decrypt to get 2m.
 * Bottom:      Proof panel on DDH, CPA security, and malleability.
 */

import { useState } from 'react'
import {
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  elgamalMalleability,
  elgamalCpaGame,
  bigintToHex,
  type ElGamalKeyPair,
  type ElGamalCiphertext,
  type MalleabilityResult,
  type CpaGameResult,
} from '../crypto/elgamal'
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

export default function Pa16ElGamalDemo() {
  // Key state
  const [keys, setKeys] = useState<ElGamalKeyPair | null>(null)
  const [revealSk, setRevealSk] = useState(false)

  // Encrypt / Decrypt
  const [msgInput, setMsgInput] = useState('42')
  const [ciphertext, setCiphertext] = useState<ElGamalCiphertext | null>(null)
  const [decrypted, setDecrypted] = useState<bigint | null>(null)

  // Malleability
  const [mallResult, setMallResult] = useState<MalleabilityResult | null>(null)
  const [mallCount, setMallCount] = useState(0)
  const [mallSuccess, setMallSuccess] = useState(0)

  // CPA game
  const [cpaRounds, setCpaRounds] = useState<CpaGameResult[]>([])

  /* ---- actions ---- */

  function handleGenKeys() {
    const kp = elgamalKeygen()
    setKeys(kp)
    setCiphertext(null)
    setDecrypted(null)
    setMallResult(null)
    setRevealSk(false)
  }

  function handleEncrypt() {
    if (!keys) return
    const m = BigInt(msgInput)
    const ct = elgamalEncrypt(keys.pk, m)
    setCiphertext(ct)
    setDecrypted(null)
  }

  function handleDecrypt() {
    if (!keys || !ciphertext) return
    const m = elgamalDecrypt(keys.sk, keys.pk, ciphertext.c1, ciphertext.c2)
    setDecrypted(m)
  }

  function handleMalleability() {
    if (!keys) return
    const m = BigInt(msgInput)
    const res = elgamalMalleability(keys.pk, keys.sk, m)
    setMallResult(res)
    setMallCount(c => c + 1)
    if (res.match) setMallSuccess(c => c + 1)
  }

  function handleCpaGame() {
    if (!keys) return
    // Pick two distinct messages in [1, p-1]
    const m0 = 100n
    const m1 = 200n
    const result = elgamalCpaGame(keys.pk, keys.sk, m0, m1)
    setCpaRounds(prev => [...prev, result])
  }

  const cpaCorrect = cpaRounds.filter(r => r.correct).length

  /* ---- render ---- */

  return (
    <div style={{ padding: 24 }}>
      <h2 style={{ marginBottom: 16 }}>PA#16 — ElGamal Public-Key Cryptosystem</h2>

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        {/* Left panel — Encrypt / Decrypt */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0 }}>ElGamal Encrypt / Decrypt</h3>

          <button style={btnStyle} onClick={handleGenKeys}>
            Generate Keys
          </button>

          {keys && (
            <div style={{ marginTop: 12 }}>
              <div style={labelStyle}>Public Key</div>
              <div style={monoStyle}>
                <div><b>p</b> = {bigintToHex(keys.pk.p)}</div>
                <div><b>g</b> = {keys.pk.g.toString()}</div>
                <div><b>q</b> = {bigintToHex(keys.pk.q)}</div>
                <div><b>h</b> = {bigintToHex(keys.pk.h)}</div>
              </div>

              <div style={{ ...labelStyle, marginTop: 12 }}>
                Private Key (sk = x){' '}
                <button
                  style={{ ...btnStyle, fontSize: 11, padding: '2px 8px' }}
                  onClick={() => setRevealSk(r => !r)}
                >
                  {revealSk ? 'Hide' : 'Reveal'}
                </button>
              </div>
              {revealSk && (
                <div style={monoStyle}>{bigintToHex(keys.sk)}</div>
              )}

              <hr style={{ borderColor: 'var(--border, #444)', margin: '14px 0' }} />

              <div style={labelStyle}>Message (number in [1, p-1])</div>
              <input
                type="text"
                value={msgInput}
                onChange={e => setMsgInput(e.target.value)}
                style={{
                  ...monoStyle,
                  width: '100%',
                  padding: '4px 8px',
                  border: '1px solid var(--border, #555)',
                  borderRadius: 4,
                  background: 'var(--bg, #111)',
                  color: 'var(--text-h, #eee)',
                  boxSizing: 'border-box',
                }}
              />

              <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                <button style={btnStyle} onClick={handleEncrypt}>Encrypt</button>
                <button
                  style={{ ...btnStyle, opacity: ciphertext ? 1 : 0.4 }}
                  onClick={handleDecrypt}
                  disabled={!ciphertext}
                >
                  Decrypt
                </button>
              </div>

              {ciphertext && (
                <div style={{ marginTop: 12 }}>
                  <div style={labelStyle}>Ciphertext</div>
                  <div style={monoStyle}>
                    <div><b>c1</b> = {bigintToHex(ciphertext.c1)}</div>
                    <div><b>c2</b> = {bigintToHex(ciphertext.c2)}</div>
                  </div>
                </div>
              )}

              {decrypted !== null && (
                <div style={{ marginTop: 12 }}>
                  <div style={labelStyle}>Decrypted</div>
                  <div style={monoStyle}>{decrypted.toString()}</div>
                  <div style={{
                    marginTop: 6,
                    fontWeight: 600,
                    color: decrypted === BigInt(msgInput) ? '#4c4' : '#f44',
                  }}>
                    {decrypted === BigInt(msgInput)
                      ? 'Roundtrip OK — decrypted matches original'
                      : 'Mismatch!'}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right panel — Malleability Attack */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0 }}>Malleability Attack</h3>

          {!keys ? (
            <p style={{ color: 'var(--text-dim, #888)' }}>
              Generate keys first (left panel).
            </p>
          ) : (
            <>
              <button style={btnStyle} onClick={handleMalleability}>
                Run Malleability Attack
              </button>

              {mallResult && (
                <div style={{ marginTop: 12 }}>
                  <div style={labelStyle}>Original plaintext</div>
                  <div style={monoStyle}>{mallResult.original.toString()}</div>

                  <div style={{ ...labelStyle, marginTop: 10 }}>Original ciphertext</div>
                  <div style={monoStyle}>
                    <div><b>c1</b> = {bigintToHex(mallResult.c1)}</div>
                    <div><b>c2</b> = {bigintToHex(mallResult.c2)}</div>
                  </div>

                  <div style={{ ...labelStyle, marginTop: 10 }}>
                    Modified ciphertext (c1, 2*c2 mod p)
                  </div>
                  <div style={monoStyle}>
                    <div><b>c1</b> = {bigintToHex(mallResult.c1)}</div>
                    <div><b>c2'</b> = {bigintToHex(mallResult.modifiedC2)}</div>
                  </div>

                  <div style={{ ...labelStyle, marginTop: 10 }}>Decrypted modified</div>
                  <div style={monoStyle}>{mallResult.decryptedModified.toString()}</div>

                  <div style={{ ...labelStyle, marginTop: 10 }}>Expected (2m mod p)</div>
                  <div style={monoStyle}>{mallResult.expected.toString()}</div>

                  <div style={{
                    marginTop: 8,
                    fontWeight: 600,
                    color: mallResult.match ? '#4c4' : '#f44',
                  }}>
                    {mallResult.match ? 'Attack succeeded: Dec(c1, 2c2) = 2m' : 'Unexpected mismatch'}
                  </div>

                  <div style={warningStyle}>
                    ElGamal is malleable — an attacker can manipulate ciphertexts without
                    knowing the secret key. This means ElGamal is only CPA-secure, NOT CCA-secure.
                  </div>

                  <div style={{ marginTop: 12, fontSize: 13 }}>
                    <b>Success rate:</b> {mallSuccess}/{mallCount}{' '}
                    ({mallCount > 0 ? ((mallSuccess / mallCount) * 100).toFixed(0) : 0}%)
                  </div>
                </div>
              )}

              <hr style={{ borderColor: 'var(--border, #444)', margin: '18px 0' }} />

              <h4 style={{ marginBottom: 8 }}>IND-CPA Game</h4>
              <button style={btnStyle} onClick={handleCpaGame}>
                Run CPA Game Round
              </button>

              {cpaRounds.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 13 }}>
                    <b>Rounds:</b> {cpaRounds.length} |{' '}
                    <b>Adversary correct:</b> {cpaCorrect}/{cpaRounds.length}{' '}
                    ({((cpaCorrect / cpaRounds.length) * 100).toFixed(1)}%)
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-dim, #888)', marginTop: 4 }}>
                    A random guesser expects ~50%. The adversary has no advantage
                    under the DDH assumption.
                  </div>
                  <div style={{ maxHeight: 180, overflowY: 'auto', marginTop: 8 }}>
                    {cpaRounds.map((r, i) => (
                      <div key={i} style={{
                        ...monoStyle,
                        fontSize: 11,
                        padding: '3px 0',
                        borderBottom: '1px solid var(--border, #333)',
                      }}>
                        Round {i + 1}: b={r.b}, guess={r.adversaryGuess},{' '}
                        <span style={{ color: r.correct ? '#4c4' : '#f44' }}>
                          {r.correct ? 'correct' : 'wrong'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Bottom — Proof panel */}
      <div style={proofPanelStyle}>
        <h3 style={{ marginTop: 0, marginBottom: 8 }}>Security Analysis</h3>

        <p>
          <b>DDH Assumption:</b> Given (g, g^a, g^b), it is computationally hard to
          distinguish g^(ab) from a random group element. ElGamal's semantic security
          (IND-CPA) reduces directly to DDH: if an adversary can distinguish
          encryptions of m0 vs m1, they can solve DDH.
        </p>

        <p>
          <b>CPA Security:</b> ElGamal is IND-CPA secure under DDH. Each encryption
          uses fresh randomness r, so the same plaintext encrypts to different
          ciphertexts each time (probabilistic encryption). The IND-CPA game above
          demonstrates that a random adversary achieves advantage ~0.
        </p>

        <p>
          <b>Malleability (no CCA security):</b> Given ciphertext (c1, c2) for message m,
          an adversary can compute (c1, k*c2 mod p) which decrypts to k*m mod p.
          This is a homomorphic property — useful in some protocols, but fatal for
          CCA security. An adversary with decryption oracle access can trivially
          recover any plaintext.
        </p>

        <p>
          <b>Achieving CCA security:</b> To obtain CCA2 security, ElGamal must be
          combined with a signature scheme or MAC (e.g., Cramer-Shoup cryptosystem,
          or encrypt-then-sign as explored in PA#17). Raw ElGamal should never be
          used where chosen-ciphertext attacks are a concern.
        </p>
      </div>
    </div>
  )
}
