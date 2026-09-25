import { useCallback, useEffect, useState } from 'react'
import { evolutionApi } from '../../services/api'

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
