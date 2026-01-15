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
  glob<T = unknown>(
    pattern: string,
    options?: {
      eager?: boolean
      query?: string
      import?: string
      as?: 'raw' | 'url'
    },
  ): Record<string, T>
}

declare module 'virtual:tips-data' {
  interface TipMetadata {
    id: string
    title: string
    status: string
    fileName: string
  }
  export const tips: TipMetadata[]
}

declare namespace NodeJS {
  interface ProcessEnv extends ImportMetaEnv {
    readonly NODE_ENV: 'development' | 'production' | 'test'
    readonly VERCEL_ENV: 'development' | 'preview' | 'production'
  }
}
