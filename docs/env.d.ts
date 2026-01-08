interface ImportMetaEnv {
  readonly VITE_ENVIRONMENT: 'local' | 'devnet' | 'testnet' | undefined
  readonly VITE_EXPLORER_OVERRIDE: string
  readonly VITE_RPC_CREDENTIALS: string
  readonly VITE_FRONTEND_API_TOKEN: string
  readonly VITE_PUBLIC_POSTHOG_KEY?: string
  readonly VITE_PUBLIC_POSTHOG_HOST?: string
  readonly MODE: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare namespace NodeJS {
  interface ProcessEnv extends ImportMetaEnv {
    readonly NODE_ENV: 'development' | 'production' | 'test'
  }
}
