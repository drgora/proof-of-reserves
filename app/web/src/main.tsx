import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { WagmiProvider, createConfig, http } from 'wagmi'
import { mainnet, sepolia, optimismSepolia, baseSepolia } from 'wagmi/chains'
import { injected } from 'wagmi/connectors'
import App from './App'
import Directory from './pages/Directory'
import AgentDetail from './pages/AgentDetail'
import ProveReserves from './pages/ProveReserves'
import Docs from './pages/Docs'
import './theme.css'

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
})

// Browser-wallet config: injected providers only (MetaMask, Rabby, …). The wallet only
// personal_signs messages — it never needs to switch network or spend gas — so the chain
// list is just to keep wagmi happy.
const wagmiConfig = createConfig({
  chains: [sepolia, baseSepolia, optimismSepolia, mainnet],
  connectors: [injected()],
  transports: {
    [sepolia.id]: http(),
    [baseSepolia.id]: http(),
    [optimismSepolia.id]: http(),
    [mainnet.id]: http(),
  },
})

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <Directory /> },
      { path: 'prove', element: <ProveReserves /> },
      { path: 'docs', element: <Docs /> },
      { path: 'agent/:agentId', element: <AgentDetail /> },
    ],
  },
])

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </WagmiProvider>
  </React.StrictMode>,
)
