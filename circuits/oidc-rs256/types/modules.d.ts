// The parts of untyped dependencies this package uses.

declare module 'snarkjs' {
  type Logger = {
    debug?(message: string): void
    error?(message: string): void
    info(message: string): void
    warn(message: string): void
  }

  type Proof = import('../src/encoding.ts').Proof
  type VerifyingKey = import('../src/encoding.ts').VerifyingKey

  export const groth16: {
    fullProve(
      input: object,
      wasm: string,
      zkey: string,
    ): Promise<{ proof: Proof; publicSignals: string[] }>
    verify(key: VerifyingKey, publicSignals: readonly string[], proof: Proof): Promise<boolean>
  }

  export const wtns: {
    check(r1cs: string, wtns: string, logger: Logger): Promise<boolean>
  }

  export const zKey: {
    beacon(
      zkey: string,
      out: string,
      name: string,
      beaconHash: string,
      iterationsExponent: number,
      logger: Logger,
    ): Promise<unknown>
    contribute(
      zkey: string,
      out: string,
      name: string,
      entropy: string,
      logger: Logger,
    ): Promise<unknown>
    exportVerificationKey(zkey: string, logger: Logger): Promise<VerifyingKey>
    newZKey(r1cs: string, ptau: string, zkey: string, logger: Logger): Promise<unknown>
  }
}

declare module 'circom_runtime' {
  export function WitnessCalculatorBuilder(
    code: Uint8Array,
    options?: { sanityCheck?: boolean },
  ): Promise<{ calculateWitness(input: object, sanityCheck: boolean): Promise<bigint[]> }>
}
