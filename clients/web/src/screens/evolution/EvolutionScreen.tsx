import { useState } from 'react'
import type { ConsoleScreenProps } from '../../shared/types'
import { Icon } from '../../shared/icons'
import { Select } from '../../shared/ui'
import { useToast } from '../../shell/toast'
import { evolutionApi } from '../../services/api'
import {
  errorText,
  usePlaybooks,
  useRunCount,
  useEvolution,
  type EvolutionCycle,
  type EvolvablePlaybook,
  type SynthesizedPlaybook,
} from './useEvolution'

// The story the tabs tell, in order: synthesize a hunt from an APT, run it a few
// times, then evolve it from what those runs could not settle.
type Tab = 'synthesize' | 'evolve'

// Evolution folds a population of finished runs; below this there is little for
// the detectors or the critic to aggregate.
const SUGGESTED_RUNS = 2

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
  const { cycles, loading, error, reload } = useEvolution()
  const { playbooks, reload: reloadPlaybooks } = usePlaybooks()
  const [tab, setTab] = useState<Tab>('synthesize')
  const [openId, setOpenId] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  const open = cycles.find((c) => c.cycle_id === openId) ?? null

  const toEvolve = (workflowId: string) => {
    reloadPlaybooks()
    setSelected(workflowId)
    setOpenId(null)
    setTab('evolve')
  }

  return (
    <div className="screen evolution-screen" style={{ padding: 16 }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button className={`btn ${tab === 'synthesize' ? '' : 'ghost'}`} onClick={() => setTab('synthesize')}>
          Synthesize
        </button>
        <button className={`btn ${tab === 'evolve' ? '' : 'ghost'}`} onClick={() => setTab('evolve')}>
          Evolve
        </button>
        <button
          className="btn ghost"
          onClick={() => {
            reload()
            reloadPlaybooks()
          }}
          style={{ marginLeft: 'auto' }}
        >
          Refresh
        </button>
      </div>

      {tab === 'synthesize' && <SynthesizePanel onEvolve={toEvolve} />}

      {tab !== 'synthesize' && loading && <p>Loading…</p>}
      {tab !== 'synthesize' && error && <p style={{ color: 'var(--danger, #c33)' }}>{error}</p>}

      {!loading && !error && tab === 'evolve' && (
        open ? (
          <CycleDetail cycle={open} onBack={() => setOpenId(null)} />
        ) : (
          <EvolvePanel
            playbooks={playbooks}
            selected={selected}
            onSelect={setSelected}
            cycles={cycles}
            onOpen={setOpenId}
            onEvolved={(cycleId) => {
              reload()
              reloadPlaybooks()
              setOpenId(cycleId)
            }}
          />
        )
      )}
    </div>
  )
}

const APT_PLACEHOLDER =
  'e.g. APT29 gains access with password spraying against service accounts, moves laterally over RDP, ' +
  'beacons to C2 over DNS with long sleep intervals, and stages data on database hosts before exfiltrating ' +
  'it over HTTPS to cloud storage.'

function SynthesizePanel({ onEvolve }: { onEvolve: (workflowId: string) => void }) {
  const { notify } = useToast()
  const [description, setDescription] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [result, setResult] = useState<SynthesizedPlaybook | null>(null)
  const [showSource, setShowSource] = useState(false)

  const ready = description.trim().length >= 20

  const synthesize = () => {
    setBusy(true)
    setErr(null)
    evolutionApi
      .synthesize(description.trim())
      .then((r) => {
        setResult(r.data as SynthesizedPlaybook)
        setShowSource(false)
        notify('ok', `Synthesized ${r.data.workflow_id}.`)
      })
      .catch((e) => setErr(errorText(e, 'Synthesis failed')))
      .finally(() => setBusy(false))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 900 }}>
      <div className="card" style={{ padding: 14 }}>
        <div style={{ fontWeight: 600, marginBottom: 4 }}>Describe the APT</div>
        <div style={{ fontSize: 13, opacity: 0.75, marginBottom: 10 }}>
          Its tradecraft becomes a hunt Playbook over your estate: hypotheses about real hosts and accounts,
          the ATT&amp;CK techniques they test, and the telemetry domains that carry their primary signal.
        </div>
        <textarea
          className="field-input"
          rows={6}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder={APT_PLACEHOLDER}
          style={{ width: '100%', resize: 'vertical', fontFamily: 'inherit' }}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
          <button
            className="btn primary"
            disabled={busy || !ready}
            style={{ opacity: busy || !ready ? 0.5 : 1 }}
            onClick={synthesize}
          >
            <Icon name="sparkle" /> {busy ? 'Synthesizing…' : 'Synthesize playbook'}
          </button>
        </div>
        {err && <div style={{ color: 'var(--crit)', fontSize: 13, marginTop: 8 }}>{err}</div>}
      </div>

      {result && (
        <SynthesizedCard
          result={result}
          showSource={showSource}
          onToggleSource={() => setShowSource((v) => !v)}
          onEvolve={() => onEvolve(result.workflow_id)}
        />
      )}
    </div>
  )
}

function SynthesizedCard({
  result,
  showSource,
  onToggleSource,
  onEvolve,
}: {
  result: SynthesizedPlaybook
  showSource: boolean
  onToggleSource: () => void
  onEvolve: () => void
}) {
  const pb = result.playbook
  return (
    <div className="card" style={{ padding: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'baseline' }}>
        <strong className="mono">{result.workflow_id}</strong>
        <span style={{ fontSize: 12, opacity: 0.7 }}>{result.path}</span>
      </div>
      <div style={{ fontSize: 13, opacity: 0.85, margin: '4px 0 14px' }}>{pb.description}</div>

      <Block n={1} title="Hypotheses">
        <ol style={{ margin: 0, paddingLeft: 18 }}>
          {pb.hypotheses.map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ol>
      </Block>

      <Block n={2} title="ATT&CK techniques">
        <Tags items={pb.attack_techniques} />
      </Block>

      <Block n={3} title="Data domains">
        <Tags items={pb.data_domains} />
      </Block>

      <Block n={4} title="Phases">
        {pb.phases.map((p) => (
          <div key={p.id}>
            {p.name} — <span className="mono">{p.agent}</span> · {p.tools.join(', ')}
          </div>
        ))}
      </Block>

      {result.warnings.length > 0 && (
        <div style={{ fontSize: 13, color: 'var(--warn, #b80)', marginBottom: 12 }}>
          {result.warnings.map((w) => (
            <div key={w}>⚠ {w}</div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="btn primary" onClick={onEvolve}>
          Run &amp; evolve →
        </button>
        <button className="btn ghost" onClick={onToggleSource}>
          {showSource ? 'Hide WORKFLOW.md' : 'View WORKFLOW.md'}
        </button>
      </div>
      {showSource && <pre style={preStyle}>{result.content}</pre>}
    </div>
  )
}

function Tags({ items }: { items: string[] }) {
  if (items.length === 0) return <div>—</div>
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {items.map((t) => (
        <span key={t} className="tag">
          {t}
        </span>
      ))}
    </div>
  )
}

function EvolvePanel({
  playbooks,
  selected,
  onSelect,
  cycles,
  onOpen,
  onEvolved,
}: {
  playbooks: EvolvablePlaybook[]
  selected: string | null
  onSelect: (id: string) => void
  cycles: EvolutionCycle[]
  onOpen: (id: string) => void
  onEvolved: (cycleId: string) => void
}) {
  const { notify } = useToast()
  const { count, running: inFlight, reload: reloadCount } = useRunCount(selected)
  const [running, setRunning] = useState(false)
  const [evolving, setEvolving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const playbook = playbooks.find((p) => p.id === selected) ?? null
  const shown = selected ? cycles.filter((c) => c.workflow_id === selected) : cycles

  const runHunt = () => {
    if (!selected) return
    setRunning(true)
    setErr(null)
    evolutionApi
      .runPlaybook(selected)
      .then((r) => notify('ok', `Hunt run ${r.data?.run_id ?? ''} enqueued. Refresh once it finishes.`))
      .catch((e) => setErr(errorText(e, 'Could not start the hunt run')))
      .finally(() => {
        setRunning(false)
        reloadCount()
      })
  }

  const evolve = () => {
    if (!selected) return
    setEvolving(true)
    setErr(null)
    evolutionApi
      .evolve(selected)
      .then((r) => {
        const cycle = r.data as EvolutionCycle
        notify(cycle.stage === 'activated' ? 'ok' : 'info', `${STAGE_LABEL[cycle.stage] ?? cycle.stage}: ${cycle.reason}`)
        onEvolved(cycle.cycle_id)
      })
      .catch((e) => setErr(errorText(e, 'Evolution cycle failed')))
      .finally(() => {
        setEvolving(false)
        reloadCount()
      })
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card" style={{ padding: 14 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ minWidth: 280, flex: '0 1 360px' }}>
            <Select
              value={selected ?? ''}
              options={playbooks.map((p) => ({ value: p.id, label: p.id }))}
              onSelect={onSelect}
              placeholder="Choose a hunt playbook…"
            />
          </div>
          <button
            className="btn ghost"
            disabled={!selected || running}
            style={{ opacity: !selected || running ? 0.5 : 1 }}
            onClick={runHunt}
          >
            {running ? 'Starting…' : 'Run hunt'}
          </button>
          <button
            className="btn primary"
            disabled={!selected || evolving}
            style={{ opacity: !selected || evolving ? 0.5 : 1 }}
            onClick={evolve}
          >
            <Icon name="sparkle" /> {evolving ? 'Evolving…' : 'Evolve playbook'}
          </button>
        </div>

        {playbook && (
          <div style={{ fontSize: 13, marginTop: 12, lineHeight: 1.6 }}>
            <div>
              {count === null ? 'Counting runs…' : `${count} run${count === 1 ? '' : 's'} to fold`}
              {inFlight > 0 && ` · ${inFlight} still running`}
              {inFlight > 0 && (
                <span style={{ opacity: 0.7 }}> — wait for them to conclude before evolving</span>
              )}
              {inFlight === 0 && count !== null && count < SUGGESTED_RUNS && (
                <span style={{ opacity: 0.7 }}>
                  {' '}— run the hunt {SUGGESTED_RUNS}–3 times first so evolution has a population to learn from
                </span>
              )}
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', marginTop: 6 }}>
              <span style={{ opacity: 0.7 }}>data_domains</span>
              <Tags items={playbook.data_domains} />
            </div>
          </div>
        )}
        {playbooks.length === 0 && (
          <div style={{ fontSize: 13, opacity: 0.7, marginTop: 10 }}>
            No hunt playbooks with declared hypotheses yet — synthesize one first.
          </div>
        )}
        {err && <div style={{ color: 'var(--crit)', fontSize: 13, marginTop: 8 }}>{err}</div>}
      </div>

      <CycleList cycles={shown} onOpen={onOpen} />
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
        {(proposal.add_phases ?? []).map((p: Record<string, any>) => (
          <div key={p.phase_id ?? p.id ?? p.name}>
            + phase: {p.name} ({p.agent_id ?? p.agent}) — {p.purpose}
          </div>
        ))}
        {proposal.edit && (
          <div style={{ marginTop: 4 }}>
            data_domains {(proposal.edit.data_domains_before ?? []).join(', ')} →{' '}
            {(proposal.edit.data_domains_after ?? []).join(', ')}
          </div>
        )}
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

const preStyle: React.CSSProperties = {
  background: 'var(--surface-2, rgba(127,127,127,0.08))',
  padding: 10,
  borderRadius: 6,
  overflowX: 'auto',
  fontSize: 12,
  marginTop: 6,
}
