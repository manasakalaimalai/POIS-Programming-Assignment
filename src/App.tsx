import { useState } from 'react'
import PoisCliqueExplorer from './pois/ui/PoisCliqueExplorer'
import Pa1Demo from './pois/ui/Pa1Demo'
import Pa2GgmVisualizer from './pois/ui/Pa2GgmVisualizer'
import Pa3CpaDemo from './pois/ui/Pa3CpaDemo'
import Pa4ModesDemo from './pois/ui/Pa4ModesDemo'
import Pa5MacDemo from './pois/ui/Pa5MacDemo'
import Pa6CcaDemo from './pois/ui/Pa6CcaDemo'
import Pa7MerkleDamgardDemo from './pois/ui/Pa7MerkleDamgardDemo'
import Pa8DlpHashDemo from './pois/ui/Pa8DlpHashDemo'
import Pa11DiffieHellmanDemo from './pois/ui/Pa11DiffieHellmanDemo'
import Pa13MillerRabinDemo from './pois/ui/Pa13MillerRabinDemo'
import './App.css'

const TABS = [
  { id: 'clique', label: 'Clique Explorer' },
  { id: 'pa1',    label: 'PA1 — OWF/PRG' },
  { id: 'pa2',    label: 'PA2 — PRF/GGM' },
  { id: 'pa3',    label: 'PA3 — CPA-Enc' },
  { id: 'pa4',    label: 'PA4 — Modes' },
  { id: 'pa5',    label: 'PA5 — MAC' },
  { id: 'pa6',    label: 'PA6 — CCA-Enc' },
  { id: 'pa7',    label: 'PA7 — Merkle-Damgård' },
  { id: 'pa8',    label: 'PA8 — DLP Hash' },
  { id: 'pa11',   label: 'PA11 — Diffie-Hellman' },
  { id: 'pa13',   label: 'PA13 — Primality' },
] as const
type TabId = (typeof TABS)[number]['id']

export default function App() {
  const [tab, setTab] = useState<TabId>('clique')

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex',
        gap: 2,
        padding: '10px 18px 0',
        borderBottom: '1px solid var(--border)',
        background: 'var(--surface)',
      }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              appearance: 'none',
              border: 'none',
              background: tab === t.id ? 'var(--accent-bg)' : 'transparent',
              color: 'var(--text-h)',
              fontFamily: 'inherit',
              fontWeight: tab === t.id ? 700 : 500,
              fontSize: 14,
              padding: '8px 16px',
              borderRadius: '8px 8px 0 0',
              cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              transition: 'background 0.15s, border-color 0.15s',
              opacity: tab === t.id ? 1 : 0.72,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1 }}>
        {tab === 'clique' && <PoisCliqueExplorer />}
        {tab === 'pa1'    && <Pa1Demo />}
        {tab === 'pa2'    && <Pa2GgmVisualizer />}
        {tab === 'pa3'    && <Pa3CpaDemo />}
        {tab === 'pa4'    && <Pa4ModesDemo />}
        {tab === 'pa5'    && <Pa5MacDemo />}
        {tab === 'pa6'    && <Pa6CcaDemo />}
        {tab === 'pa7'    && <Pa7MerkleDamgardDemo />}
        {tab === 'pa8'    && <Pa8DlpHashDemo />}
        {tab === 'pa11'   && <Pa11DiffieHellmanDemo />}
        {tab === 'pa13'   && <Pa13MillerRabinDemo />}
      </div>
    </div>
  )
}
