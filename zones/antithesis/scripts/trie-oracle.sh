#!/bin/sh
# Copies a zone node's log from stdin to stdout and turns reth's own trie self-checks into
# Antithesis assertions. reth recomputes a state root serially when the sparse-trie task fails or
# returns a wrong root, so those paths never make a block invalid or split the nodes: they only
# log. Each assertion is AlwaysOrUnreachable and is reported only when the log shows it failing.
# $1 is the node name. Assertions go to $ANTITHESIS_OUTPUT_DIR/sdk.jsonl when Antithesis sets it,
# or to $ANTITHESIS_SDK_LOCAL_OUTPUT for local runs; without either the log just passes through.
set -eu

OUT=
if [ -n "${ANTITHESIS_OUTPUT_DIR:-}" ]; then
    OUT="$ANTITHESIS_OUTPUT_DIR/sdk.jsonl"
elif [ -n "${ANTITHESIS_SDK_LOCAL_OUTPUT:-}" ]; then
    OUT="$ANTITHESIS_SDK_LOCAL_OUTPUT"
fi

exec awk -v node="zone-$1" -v out="$OUT" '
function esc(s) {
    gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/\t/, " ", s)
    return substr(s, 1, 2000)
}
function emit(msg, hit, line) {
    if (out == "") return
    printf "{\"antithesis_assert\":{\"assert_type\":\"always\",\"display_type\":\"AlwaysOrUnreachable\",\"condition\":false,\"hit\":%s,\"must_hit\":false,\"id\":\"%s\",\"message\":\"%s\",\"location\":{\"file\":\"zones/antithesis/scripts/trie-oracle.sh\",\"function\":\"%s\",\"class\":\"\",\"begin_line\":0,\"begin_column\":0},\"details\":{\"node\":\"%s\",\"log\":\"%s\"}}}\n", hit, msg, msg, node, node, esc(line) >> out
    fflush(out)
}
BEGIN {
    m_fail = "Sparse trie state root task never fails"
    m_root = "Sparse trie state root matches the block"
    m_upd = "Sparse trie updates match the serial computation"
    if (out != "") {
        printf "{\"antithesis_sdk\":{\"language\":{\"name\":\"shell\",\"version\":\"0\"},\"sdk_version\":\"0.3.0\",\"protocol_version\":\"1.1.0\"}}\n" >> out
        emit(m_fail, "false", ""); emit(m_root, "false", ""); emit(m_upd, "false", "")
    }
}
{ print; fflush() }
/State root task failed|State root task dropped/ { emit(m_fail, "true", $0) }
/State root task returned incorrect state root/ { emit(m_root, "true", $0) }
/Difference in (account|storage) trie updates|Difference in removed (account|storage) trie nodes|Error comparing trie updates/ { emit(m_upd, "true", $0) }
'
