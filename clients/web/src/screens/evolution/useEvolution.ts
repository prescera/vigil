import { useCallback, useEffect, useState } from 'react'
import { evolutionApi, workflowApi } from '../../services/api'

export interface EvolutionCycle {
  cycle_id: string
  workflow_id: string
  stage: string
  hypothesis_id: string | null
  tier: string | null
  detected: Record<string, any>
  proposal: Record<string, any>
  ab: Record<string, any>
  confidence: number
  reason: string
  created_at: string
}

export interface DetectorRule {
  id: string
  when: Record<string, any>
  then: Record<string, any>
  origin: Record<string, any>
  enabled: boolean
}

interface EvolutionData {
  cycles: EvolutionCycle[]
  detectors: DetectorRule[]
  loading: boolean
  error: string | null
  reload: () => void
}

export function useEvolution(): EvolutionData {
  const [cycles, setCycles] = useState<EvolutionCycle[]>([])
  const [detectors, setDetectors] = useState<DetectorRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(() => {
    setLoading(true)
    setError(null)
    Promise.all([evolutionApi.listCycles(), evolutionApi.listDetectors()])
      .then(([c, d]) => {
        setCycles((c.data?.cycles ?? []) as EvolutionCycle[])
        setDetectors((d.data?.detectors ?? []) as DetectorRule[])
      })
      .catch((e) => setError(e?.message ?? 'Failed to load evolution data'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    reload()
  }, [reload])

  return { cycles, detectors, loading, error, reload }
}

/** A file-based hunt with declared hypotheses — what Evolve can act on. */
export interface EvolvablePlaybook {
  id: string
  name: string
  description: string
  hypotheses: string[]
  data_domains: string[]
}

/** What POST /evolution/synthesize wrote. */
export interface SynthesizedPlaybook {
  workflow_id: string
  path: string
  playbook: {
    description: string
    use_case: string
    hypotheses: string[]
    attack_techniques: string[]
    data_domains: string[]
    phases: { id: string; agent: string; name: string; tools: string[] }[]
  }
  content: string
  warnings: string[]
}

export function usePlaybooks() {
  const [playbooks, setPlaybooks] = useState<EvolvablePlaybook[]>([])
  const reload = useCallback(() => {
    evolutionApi
      .listPlaybooks()
      .then((r) => setPlaybooks((r.data?.playbooks ?? []) as EvolvablePlaybook[]))
      .catch(() => setPlaybooks([]))
  }, [])
  useEffect(() => {
    reload()
  }, [reload])
  return { playbooks, reload }
}

/** Runs the miner would fold for a workflow, and how many of those are still
 * in flight (the miner folds any run with a distil, unfinished ones included);
 * null until known. */
export function useRunCount(workflowId: string | null) {
  const [count, setCount] = useState<number | null>(null)
  const [running, setRunning] = useState(0)
  const reload = useCallback(() => {
    if (!workflowId) return setCount(null)
    evolutionApi
      .stats(workflowId)
      .then((r) => setCount(Number(r.data?.run_count ?? 0)))
      .catch(() => setCount(null))
    workflowApi
      .listRuns(workflowId, { status: 'running', limit: 200 })
      .then((r) => setRunning((r.data?.runs ?? []).length))
      .catch(() => setRunning(0))
  }, [workflowId])
  useEffect(() => {
    reload()
  }, [reload])
  return { count, running, reload }
}

/** The API's `detail`, else the transport error. */
export function errorText(e: any, fallback: string): string {
  return e?.response?.data?.detail ?? e?.message ?? fallback
}
