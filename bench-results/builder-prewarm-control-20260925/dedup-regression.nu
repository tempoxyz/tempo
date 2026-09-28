source harness/tempo.nu

let base = ["--builder.disable-prewarming" "--engine.disable-execution-cache-sharing-with-builder" "--rpc-cache.max-blocks" "128"]
let result = (dedup-args $base ["--builder.disable-prewarming"])
if $result != ["--engine.disable-execution-cache-sharing-with-builder" "--rpc-cache.max-blocks" "128" "--builder.disable-prewarming"] {
    error make {msg: "Boolean override swallowed adjacent flag"}
}
let valued = (dedup-args ["--rpc-cache.max-blocks" "128" "--builder.disable-prewarming"] ["--rpc-cache.max-blocks" "256"])
if $valued != ["--builder.disable-prewarming" "--rpc-cache.max-blocks" "256"] {
    error make {msg: "Value override regressed"}
}
let inline = (dedup-args ["--rpc-cache.max-blocks=128" "--builder.disable-prewarming"] ["--rpc-cache.max-blocks=256"])
if $inline != ["--builder.disable-prewarming" "--rpc-cache.max-blocks=256"] {
    error make {msg: "Inline value override regressed"}
}
let unchanged = (dedup-args $base [])
if $unchanged != $base { error make {msg: "Empty override changed arguments"} }
print "PASS: boolean, valued, inline, and empty overrides"
