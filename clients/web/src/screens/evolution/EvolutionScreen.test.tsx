import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import EvolutionScreen from './EvolutionScreen'
import { evolutionApi } from '../../services/api'

const notify = vi.fn()
vi.mock('../../shell/toast', () => ({ useToast: () => ({ notify }) }))

const PLAYBOOK = {
  id: 'apt29-finance-hunt',
  name: 'apt29-finance-hunt',
  description: 'Hunts APT29 tradecraft in the finance unit.',
  hypotheses: ['fin-db-01 is beaconing to external C2 over DNS'],
  data_domains: ['dns', 'auth'],
}

const CYCLE = {
  cycle_id: 'cyc-apt29-finance-hunt-1',
  workflow_id: 'apt29-finance-hunt',
  stage: 'activated',
  hypothesis_id: 'h-1',
  tier: 'tier2',
  detected: {},
  proposal: {
    add_data_domains: ['endpoint'],
    add_phases: [],
    edit: { data_domains_before: ['dns', 'auth'], data_domains_after: ['dns', 'auth', 'endpoint'] },
    rationale: 'add endpoint',
  },
  ab: {},
  confidence: 0.95,
  reason: 'auto-activated',
  created_at: '2026-10-05T00:00:00',
}

vi.mock('../../services/api', () => ({
  workflowApi: { listRuns: vi.fn(() => Promise.resolve({ data: { runs: [] } })) },
  evolutionApi: {
    listCycles: vi.fn(),
    listDetectors: vi.fn(() => Promise.resolve({ data: { detectors: [] } })),
    listPlaybooks: vi.fn(() => Promise.resolve({ data: { playbooks: [PLAYBOOK] } })),
    stats: vi.fn(() => Promise.resolve({ data: { run_count: 3 } })),
    synthesize: vi.fn(() =>
      Promise.resolve({
        data: {
          workflow_id: 'apt29-finance-hunt',
          path: 'core/workflows/definitions/apt29-finance-hunt/WORKFLOW.md',
          playbook: {
            description: PLAYBOOK.description,
            use_case: '',
            hypotheses: PLAYBOOK.hypotheses,
            attack_techniques: ['T1071.004'],
            data_domains: PLAYBOOK.data_domains,
            phases: [{ id: 'threat_hunter', agent: 'threat_hunter', name: 'Hunt', tools: ['search_findings'] }],
          },
          content: '---\nname: apt29-finance-hunt\n---\n',
          warnings: [],
        },
      }),
    ),
    runPlaybook: vi.fn(() => Promise.resolve({ data: { run_id: 'run-1' } })),
    evolve: vi.fn(() => Promise.resolve({ data: CYCLE })),
  },
}))

describe('EvolutionScreen', () => {
  it('synthesizes a playbook from an APT, then evolves it', async () => {
    let cycles: unknown[] = []
    vi.mocked(evolutionApi.listCycles).mockImplementation(() => Promise.resolve({ data: { cycles } }) as never)

    render(<EvolutionScreen openChat={vi.fn()} go={vi.fn()} goSettings={vi.fn()} setViewFull={vi.fn()} />)

    expect(screen.queryByRole('button', { name: 'Cycles' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Evolve' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Detectors' })).toBeNull()
    const synth = screen.getByRole('button', { name: /Synthesize playbook/ })
    expect(synth).toBeDisabled()

    fireEvent.change(screen.getByPlaceholderText(/APT29 gains access/), {
      target: { value: 'APT29 beacons over DNS and reuses service account credentials.' },
    })
    fireEvent.click(synth)

    expect(await screen.findByText('fin-db-01 is beaconing to external C2 over DNS')).toBeInTheDocument()
    expect(evolutionApi.synthesize).toHaveBeenCalledWith(
      'APT29 beacons over DNS and reuses service account credentials.',
    )

    fireEvent.click(screen.getByRole('button', { name: /Run & evolve/ }))
    expect(await screen.findByText(/3 runs to fold/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Run hunt' }))
    await waitFor(() => expect(evolutionApi.runPlaybook).toHaveBeenCalledWith('apt29-finance-hunt'))

    cycles = [CYCLE]
    fireEvent.click(screen.getByRole('button', { name: /Evolve playbook/ }))
    await waitFor(() => expect(evolutionApi.evolve).toHaveBeenCalledWith('apt29-finance-hunt'))
    expect(await screen.findByText(/data_domains dns, auth → dns, auth, endpoint/)).toBeInTheDocument()
  })
})
