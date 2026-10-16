import Freigen.F2Z.Examples.EcdsaP256.Radix32Production
import Freigen.F2Z.Serialization

open Freigen.F2Z

/-- Serialize the production ECDSA-P256 `verifyDigestCS` constraint system
(PR #14) to the binary M/A/B/C format of `Freigen.F2Z.Serialization`. -/
def main (args : List String) : IO Unit := do
  let path := args.headD "verify_digest_cs.bin"
  let cs := Examples.EcdsaP256.verifyDigestCS.2
  let stats := cs.stats
  IO.println s!"mRows={stats.mRows} mCols={stats.mCols} r1csRows={stats.r1csRows}"
  cs.writeBinFile path
  IO.println s!"wrote {path}"
