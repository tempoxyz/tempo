interface ImportMetaEnv {
  readonly VITE_INDEXSUPPLY_API_URL: string
  readonly VITE_LOCAL: string
  readonly VITE_RPC_CREDENTIALS: string
  readonly VITE_LOCAL_EXPLORER: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
