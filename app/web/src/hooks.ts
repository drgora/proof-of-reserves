import { useQuery } from '@tanstack/react-query'
import { api } from './api'

export const useOverview = () =>
  useQuery({ queryKey: ['overview'], queryFn: api.overview, staleTime: 30_000 })

export const useDirectory = () =>
  useQuery({ queryKey: ['agents'], queryFn: api.agents, staleTime: 30_000 })

export const useAgent = (id: string | undefined) =>
  useQuery({
    queryKey: ['agent', id],
    queryFn: () => api.agent(id as string),
    enabled: !!id,
    staleTime: 30_000,
  })

// The submission pipeline is live-polled (the skill recommends a 3–5s cadence
// so users watch stages advance). It's gated server-side: when no submitter
// status source is wired the proxy returns { enabled:false }, and this stays quiet.
export const usePipeline = () =>
  useQuery({
    queryKey: ['pipeline'],
    queryFn: api.pipeline,
    refetchInterval: 3_000,
    staleTime: 0,
  })
