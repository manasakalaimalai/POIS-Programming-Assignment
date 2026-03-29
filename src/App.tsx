import { useState } from 'react'
import PoisCliqueExplorer from './pois/ui/PoisCliqueExplorer'
import Pa1Demo from './pois/ui/Pa1Demo'
import Pa2GgmVisualizer from './pois/ui/Pa2GgmVisualizer'
import Pa3CpaDemo from './pois/ui/Pa3CpaDemo'
import Pa5MacDemo from './pois/ui/Pa5MacDemo'
import './App.css'

const TABS = [
  { id: 'clique', label: 'Clique Explorer' },
  { id: 'pa1',    label: 'PA1 — OWF/PRG' },
  { id: 'pa2',    label: 'PA2 — PRF/GGM' },
  { id: 'pa3',    label: 'PA3 — CPA-Enc' },
  { id: 'pa5',    label: 'PA5 — MAC' },
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
        {tab === 'pa5'    && <Pa5MacDemo />}
      </div>
    </div>
  )
}
