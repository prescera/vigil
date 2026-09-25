import { useState } from 'react'
import type { ConsoleScreenProps } from '../../shared/types'
import { useEvolution, type EvolutionCycle, type DetectorRule } from './useEvolution'

type Tab = 'cycles' | 'detectors'

const STAGE_LABEL: Record<string, string> = {
  activated: '● Activated',
  parked: '● Awaiting approval',
  proposed: '● Proposed',
  rejected: '● Rejected',
  'data-starved': '— Routed to integrations',
  'no-gap': '— No gap',
  'no-runs': '— No runs',
}

function tierBadge(c: EvolutionCycle): string {
  if (c.tier === 'tier2') return '🔎 blindspot-critic'
  if (c.tier === 'tier1') return `⚙ rule: ${c.detected?.rule_id ?? 'tier-1'}`
  return 'ℹ diagnostic'
}

export default function EvolutionScreen(_props: ConsoleScreenProps) {
  const { cycles, detectors, loading, error, reload } = useEvolution()
  const [tab, setTab] = useState<Tab>('cycles')
  const [openId, setOpenId] = useState<string | null>(null)

  const open = cycles.find((c) => c.cycle_id === openId) ?? null

  return (
    <div className="screen evolution-screen" style={{ padding: 16 }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button className={`btn ${tab === 'cycles' ? '' : 'ghost'}`} onClick={() => setTab('cycles')}>
          Cycles
        </button>
        <button className={`btn ${tab === 'detectors' ? '' : 'ghost'}`} onClick={() => setTab('detectors')}>
          Detectors
        </button>
        <button className="btn ghost" onClick={reload} style={{ marginLeft: 'auto' }}>
          Refresh
        </button>
      </div>

      {loading && <p>Loading…</p>}
      {error && <p style={{ color: 'var(--danger, #c33)' }}>{error}</p>}

      {!loading && !error && tab === 'cycles' && (
        open ? (
          <CycleDetail cycle={open} onBack={() => setOpenId(null)} />
        ) : (
          <CycleList cycles={cycles} onOpen={setOpenId} />
        )
      )}

      {!loading && !error && tab === 'detectors' && <DetectorList detectors={detectors} />}
    </div>
  )
}

function CycleList({ cycles, onOpen }: { cycles: EvolutionCycle[]; onOpen: (id: string) => void }) {
  if (cycles.length === 0) return <p>No evolution cycles yet.</p>
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {cycles
        .slice()
        .reverse()
        .map((c) => (
          <button
            key={c.cycle_id}
            className="card"
            onClick={() => onOpen(c.cycle_id)}
            style={{ textAlign: 'left', padding: 14, cursor: 'pointer' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
              <strong>{c.workflow_id}</strong>
              <span>{STAGE_LABEL[c.stage] ?? c.stage}</span>
            </div>
            <div style={{ fontSize: 13, opacity: 0.85, marginTop: 4 }}>
              {tierBadge(c)}
              {c.hypothesis_id ? ` · ${c.hypothesis_id}` : ''}
            </div>
            <div style={{ fontSize: 13, opacity: 0.7, marginTop: 4 }}>{c.reason}</div>
          </button>
        ))}
    </div>
  )
}

function Block({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontWeight: 600, marginBottom: 6 }}>
        {n} {title}
      </div>
      <div style={{ fontSize: 13, lineHeight: 1.5 }}>{children}</div>
    </div>
  )
}

function CycleDetail({ cycle, onBack }: { cycle: EvolutionCycle; onBack: () => void }) {
  const ab = cycle.ab ?? {}
  const proposal = cycle.proposal ?? {}
  const detected = cycle.detected ?? {}
  return (
    <div>
      <button className="btn ghost" onClick={onBack} style={{ marginBottom: 12 }}>
        ← All cycles
      </button>
      <h3 style={{ marginBottom: 4 }}>
        {cycle.workflow_id} · {cycle.cycle_id}
      </h3>
      <div style={{ opacity: 0.8, marginBottom: 16 }}>{STAGE_LABEL[cycle.stage] ?? cycle.stage}</div>

      <Block n={1} title={`Detected — ${tierBadge(cycle)}`}>
        <div>{cycle.hypothesis_id}</div>
        <pre style={preStyle}>{JSON.stringify(detected.stat_refs ?? detected, null, 2)}</pre>
      </Block>

      <Block n={2} title="Diagnosis">
        <div>{detected.reason ?? cycle.reason}</div>
      </Block>

      <Block n={3} title="Proposed change">
        <div>+ data_domains: {(proposal.add_data_domains ?? []).join(', ') || '—'}</div>
        <div style={{ opacity: 0.8, marginTop: 4 }}>{proposal.rationale}</div>
      </Block>

      <Block n={4} title="Validation (A/B over frozen snapshot)">
        {Object.keys(ab).length === 0 ? (
          <div>Not yet validated.</div>
        ) : (
          <div>
            <div>
              target flipped: {String(ab.target_flipped)} · non-regressing: {String(ab.non_regressing)}
            </div>
            <div>
              score {ab.score_before} → {ab.score_after}
            </div>
          </div>
        )}
      </Block>

      <div style={{ opacity: 0.8 }}>
        confidence {cycle.confidence} · {cycle.reason}
      </div>
    </div>
  )
}

function DetectorList({ detectors }: { detectors: DetectorRule[] }) {
  if (detectors.length === 0)
    return <p>No Tier-1 detectors yet — they crystallise from validated Tier-2 discoveries.</p>
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {detectors.map((d) => (
        <div key={d.id} className="card" style={{ padding: 14 }}>
          <strong>{d.id}</strong>
          <div style={{ fontSize: 13, opacity: 0.8, marginTop: 4 }}>
            origin: {d.origin?.discovered_by ?? '—'} · {d.origin?.first_cycle ?? ''} · validated{' '}
            {d.origin?.validated_cycles ?? 0} cycles
          </div>
          <pre style={preStyle}>{JSON.stringify(d.when, null, 2)}</pre>
        </div>
      ))}
    </div>
  )
}

const preStyle: React.CSSProperties = {
  background: 'var(--surface-2, rgba(127,127,127,0.08))',
  padding: 10,
  borderRadius: 6,
  overflowX: 'auto',
  fontSize: 12,
  marginTop: 6,
}
