#!/bin/sh
# Antithesis SDK assertions from shell: JSON lines in $ANTITHESIS_OUTPUT_DIR/sdk.jsonl, or stdout
# when run outside Antithesis. Source this file. printf, not echo: dash's echo expands the
# backslash escapes jq writes into JSON strings.

sdk_emit() {
    if [ -n "${ANTITHESIS_OUTPUT_DIR:-}" ]; then
        mkdir -p "$ANTITHESIS_OUTPUT_DIR"
        printf '%s\n' "$1" >> "$ANTITHESIS_OUTPUT_DIR/sdk.jsonl"
    else
        printf '%s\n' "$1"
    fi
}

# sdk_assert <always|sometimes> <hit:true|false> <condition:true|false> <message> [details JSON]
sdk_assert() {
    case "$1" in
        always) display=Always ;;
        sometimes) display=Sometimes ;;
        *) echo "sdk_assert: unknown type $1" >&2; return 1 ;;
    esac
    sdk_emit "$(jq -cn --arg type "$1" --arg display "$display" --argjson hit "$2" \
        --argjson condition "$3" --arg message "$4" --argjson details "${5:-null}" \
        --arg file "${0##*/}" '{antithesis_assert: {
            assert_type: $type, display_type: $display, hit: $hit, must_hit: true,
            condition: $condition, id: $message, message: $message, details: $details,
            location: {file: $file, function: "", class: "", begin_line: 0, begin_column: 0}
        }}')"
}

# Declares an assertion before it can fire, so Antithesis reports it even if it never does.
sdk_declare() {
    sdk_assert "$1" false true "$2"
}
