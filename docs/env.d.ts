interface ImportMetaEnv {
  readonly VITE_LOCAL: string
  readonly VITE_RPC_CREDENTIALS: string
  readonly VITE_LOCAL_EXPLORER: string
  readonly VITE_FRONTEND_API_TOKEN: string
  readonly VITE_PUBLIC_POSTHOG_KEY?: string
  readonly VITE_PUBLIC_POSTHOG_HOST?: string
  readonly MODE: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
