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
