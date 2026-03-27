/**
 * PA#17 — CCA-Secure PKC (Encrypt-then-Sign) Demo
 *
 * Two-column layout comparing plain ElGamal (malleable) vs
 * Encrypt-then-Sign (CCA2-secure). Bottom proof panel explains
 * why signatures block malleability attacks.
 */

import { useState } from 'react'
import { bigintToHex, elgamalEncrypt } from '../crypto/elgamal'
import {
  ccaPkcKeygen,
  ccaPkcEncrypt,
  ccaPkcDecrypt,
  ccaMalleabilityBlocked,
  plainElGamalMalleability,
  type CcaPkcKeyBundle,
  type CcaPkcCiphertext,
  type CcaMalleabilityBlockedResult,
  type PlainElGamalMalleabilityResult,
} from '../crypto/ccaPkc'
import { DH_PARAMS } from '../crypto/diffieHellman'
import { bigintToBytes } from '../crypto/rsa'
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

const successStyle: React.CSSProperties = {
  background: 'rgba(50, 200, 80, 0.12)',
  border: '1px solid rgba(50, 200, 80, 0.4)',
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

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Pa17CcaPkcDemo() {
  const [keys, setKeys] = useState<CcaPkcKeyBundle | null>(null)
  const [msgInput, setMsgInput] = useState('42')

  // Left panel: plain ElGamal
  const [plainCt, setPlainCt] = useState<{ c1: bigint; c2: bigint } | null>(null)
  const [plainModC2, setPlainModC2] = useState<bigint | null>(null)
  const [plainMallResult, setPlainMallResult] = useState<PlainElGamalMalleabilityResult | null>(null)

  // Right panel: Encrypt-then-Sign
  const [etsCt, setEtsCt] = useState<CcaPkcCiphertext | null>(null)
  const [etsDecrypted, setEtsDecrypted] = useState<string | null>(null)
  const [etsModC2, setEtsModC2] = useState<bigint | null>(null)
  const [etsMallResult, setEtsMallResult] = useState<CcaMalleabilityBlockedResult | null>(null)

  /* ---- actions ---- */

  function handleGenKeys() {
    const k = ccaPkcKeygen(64)
    setKeys(k)
    setPlainCt(null)
    setPlainModC2(null)
    setPlainMallResult(null)
    setEtsCt(null)
    setEtsDecrypted(null)
    setEtsModC2(null)
    setEtsMallResult(null)
  }

  // --- Left panel: plain ElGamal ---

  function handlePlainEncrypt() {
    if (!keys) return
    const m = BigInt(msgInput)
    const ct = elgamalEncrypt(keys.encKeys.pk, m)
    setPlainCt(ct)
    setPlainModC2(null)
    setPlainMallResult(null)
  }

  function handlePlainModify() {
    if (!plainCt) return
    const { p } = DH_PARAMS
    setPlainModC2((2n * plainCt.c2) % p)
  }

  function handlePlainDecryptModified() {
    if (!keys) return
    const m = BigInt(msgInput)
    const res = plainElGamalMalleability(keys.encKeys, m)
    setPlainMallResult(res)
  }

  // --- Right panel: Encrypt-then-Sign ---

  function handleEtsEncrypt() {
    if (!keys) return
    const m = BigInt(msgInput)
    const mByteLen = Math.max(1, Math.ceil(m.toString(16).length / 2))
    const mBytes = bigintToBytes(m, mByteLen)
    const ct = ccaPkcEncrypt(keys.encKeys.pk, keys.sigKeys.sk, mBytes)
    setEtsCt(ct)
    setEtsModC2(null)
    setEtsMallResult(null)

    // Also decrypt to show roundtrip
    const dec = ccaPkcDecrypt(
      keys.encKeys.sk, keys.encKeys.pk, keys.sigKeys.pk,
      ct.c1, ct.c2, ct.sigma,
    )
    setEtsDecrypted(dec)
  }

  function handleEtsModify() {
    if (!etsCt) return
    const { p } = DH_PARAMS
    setEtsModC2((2n * etsCt.c2) % p)
  }

  function handleEtsMalleability() {
    if (!keys) return
    const m = BigInt(msgInput)
    const res = ccaMalleabilityBlocked(keys.encKeys, keys.sigKeys, m)
    setEtsMallResult(res)
  }

  /* ---- render ---- */

  return (
    <div style={{ padding: 24 }}>
      <h2 style={{ marginBottom: 16 }}>PA#17 — CCA-Secure PKC (Encrypt-then-Sign)</h2>

      <div style={{ marginBottom: 16 }}>
        <button style={btnStyle} onClick={handleGenKeys}>
          Generate Keys (ElGamal + RSA)
        </button>
        {keys && (
          <span style={{ marginLeft: 12, fontSize: 13, color: 'var(--text-dim, #888)' }}>
            ElGamal pk.h = {bigintToHex(keys.encKeys.pk.h)}, RSA N = {bigintToHex(keys.sigKeys.pk.N)}
          </span>
        )}
      </div>

      {keys && (
        <div style={{ marginBottom: 12 }}>
          <div style={labelStyle}>Message (number in [1, p-1])</div>
          <input
            type="text"
            value={msgInput}
            onChange={e => setMsgInput(e.target.value)}
            style={{
              ...monoStyle,
              width: 300,
              padding: '4px 8px',
              border: '1px solid var(--border, #555)',
              borderRadius: 4,
              background: 'var(--bg, #111)',
              color: 'var(--text-h, #eee)',
            }}
          />
        </div>
      )}

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        {/* Left panel — Plain ElGamal (CPA-only, Malleable) */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0, color: '#f88' }}>Plain ElGamal (CPA-only)</h3>

          {!keys ? (
            <p style={{ color: 'var(--text-dim, #888)' }}>Generate keys first.</p>
          ) : (
            <>
              <button style={btnStyle} onClick={handlePlainEncrypt}>
                Encrypt
              </button>

              {plainCt && (
                <div style={{ marginTop: 12 }}>
                  <div style={labelStyle}>Ciphertext</div>
                  <div style={monoStyle}>
                    <div><b>c1</b> = {bigintToHex(plainCt.c1)}</div>
                    <div><b>c2</b> = {bigintToHex(plainCt.c2)}</div>
                  </div>

                  <div style={{ marginTop: 10 }}>
                    <button style={btnStyle} onClick={handlePlainModify}>
                      Multiply c2 by 2
                    </button>
                  </div>

                  {plainModC2 !== null && (
                    <div style={{ marginTop: 10 }}>
                      <div style={labelStyle}>Modified ciphertext</div>
                      <div style={monoStyle}>
                        <div><b>c1</b> = {bigintToHex(plainCt.c1)}</div>
                        <div><b>c2'</b> = {bigintToHex(plainModC2)}</div>
                      </div>

                      <button
                        style={{ ...btnStyle, marginTop: 10 }}
                        onClick={handlePlainDecryptModified}
                      >
                        Decrypt Modified
                      </button>
                    </div>
                  )}

                  {plainMallResult && (
                    <div style={{ marginTop: 12 }}>
                      <div style={labelStyle}>Decrypted modified</div>
                      <div style={monoStyle}>
                        {plainMallResult.decryptedModified.toString()}
                      </div>
                      <div style={{ marginTop: 4, fontSize: 13 }}>
                        <b>Original m:</b> {plainMallResult.originalM.toString()} |{' '}
                        <b>Got:</b> {plainMallResult.decryptedModified.toString()} = 2m mod p
                      </div>

                      <div style={warningStyle}>
                        ElGamal is malleable — attacker changed plaintext from{' '}
                        {plainMallResult.originalM.toString()} to{' '}
                        {plainMallResult.decryptedModified.toString()} without the secret key.
                        Only CPA-secure, NOT CCA-secure.
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Right panel — Encrypt-then-Sign (CCA-secure) */}
        <div style={panelStyle}>
          <h3 style={{ marginTop: 0, color: '#4c4' }}>Encrypt-then-Sign (CCA-secure)</h3>

          {!keys ? (
            <p style={{ color: 'var(--text-dim, #888)' }}>Generate keys first.</p>
          ) : (
            <>
              <button style={btnStyle} onClick={handleEtsEncrypt}>
                Encrypt-then-Sign
              </button>

              {etsCt && (
                <div style={{ marginTop: 12 }}>
                  <div style={labelStyle}>Signcrypted ciphertext</div>
                  <div style={monoStyle}>
                    <div><b>c1</b> = {bigintToHex(etsCt.c1)}</div>
                    <div><b>c2</b> = {bigintToHex(etsCt.c2)}</div>
                    <div><b>sigma</b> = {bigintToHex(etsCt.sigma)}</div>
                  </div>

                  {etsDecrypted !== null && (
                    <div style={{ marginTop: 8 }}>
                      <div style={labelStyle}>Decrypted (roundtrip)</div>
                      <div style={monoStyle}>{etsDecrypted}</div>
                    </div>
                  )}

                  <div style={{ marginTop: 10 }}>
                    <button style={btnStyle} onClick={handleEtsModify}>
                      Multiply c2 by 2
                    </button>
                  </div>

                  {etsModC2 !== null && (
                    <div style={{ marginTop: 10 }}>
                      <div style={labelStyle}>Modified ciphertext (same sigma)</div>
                      <div style={monoStyle}>
                        <div><b>c1</b> = {bigintToHex(etsCt.c1)}</div>
                        <div><b>c2'</b> = {bigintToHex(etsModC2)}</div>
                        <div><b>sigma</b> = {bigintToHex(etsCt.sigma)} (unchanged)</div>
                      </div>

                      <button
                        style={{ ...btnStyle, marginTop: 10 }}
                        onClick={handleEtsMalleability}
                      >
                        Attempt Decrypt Modified
                      </button>
                    </div>
                  )}

                  {etsMallResult && (
                    <div style={{ marginTop: 12 }}>
                      <div style={labelStyle}>Signature verification</div>
                      <div style={{
                        ...monoStyle,
                        color: etsMallResult.signatureValid ? '#4c4' : '#f55',
                        fontWeight: 700,
                      }}>
                        {etsMallResult.signatureValid ? 'VALID' : 'INVALID -- signature mismatch'}
                      </div>

                      <div style={{ ...labelStyle, marginTop: 8 }}>Decrypt result</div>
                      <div style={{ ...monoStyle, fontWeight: 700 }}>
                        {etsMallResult.decryptResult === null ? 'null (rejected)' : etsMallResult.decryptResult}
                      </div>

                      <div style={successStyle}>
                        Signature blocks malleability — modified ciphertext is rejected.
                        The Encrypt-then-Sign construction provides CCA2 security.
                      </div>
                    </div>
                  )}
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
          <b>Encrypt-then-Sign Construction:</b> To encrypt message m for receiver R
          with sender S's signing key: (1) ElGamal-encrypt m under R's public key to
          get (c1, c2), (2) sign the serialized ciphertext c1||c2 under S's RSA signing
          key to get sigma, (3) transmit (c1, c2, sigma). To decrypt, first verify sigma,
          then ElGamal-decrypt only if the signature is valid.
        </p>

        <p>
          <b>CCA2 Security:</b> The signature acts as a non-malleable authentication tag
          on the ciphertext. Any modification to c1 or c2 invalidates sigma, causing the
          receiver to reject. This prevents the chosen-ciphertext attacks that exploit
          ElGamal's multiplicative homomorphism. An adversary who submits a modified
          ciphertext to the decryption oracle gets nothing (null/reject), so no information
          about the plaintext leaks.
        </p>

        <p>
          <b>Why plain ElGamal fails CCA:</b> Given ciphertext (c1, c2) for message m,
          an adversary computes (c1, k*c2 mod p) and asks the decryption oracle for the
          result. The oracle returns k*m mod p, from which the adversary recovers m. The
          left panel demonstrates this with k=2.
        </p>

        <p>
          <b>Dependency lineage:</b> PA#17 (CCA PKC) builds on PA#15 (RSA Digital
          Signatures) + PA#16 (ElGamal PKC), which in turn depend on PA#12 (RSA) +
          PA#11 (Diffie-Hellman), which depend on PA#13 (Miller-Rabin Primality).
        </p>
      </div>
    </div>
  )
}
