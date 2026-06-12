import Lake
open Lake DSL

package tempo_formal where
  version := v!"0.1.0"

@[default_target]
lean_lib Tempo where
  roots := #[`Tempo]
