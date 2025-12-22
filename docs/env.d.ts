interface ImportMetaEnv {
  readonly VITE_ENVIRONMENT: 'local' | 'devnet' | 'testnet' | undefined
  readonly VITE_EXPLORER_OVERRIDE: string
  readonly VITE_RPC_CREDENTIALS: string
  readonly VITE_FRONTEND_API_TOKEN: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
