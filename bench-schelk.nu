#!/usr/bin/env nu

def clean-marker [state_path: string] {
    let marker_dir = ($env.BENCH_SCHELK_MARKER_DIR? | default $env.HOME)
    let stem = ($state_path | path parse | get stem)
    $"($marker_dir)/.tempo-bench-schelk-clean-($stem)"
}

def schelk-state [state_path: string] {
    sudo cat $state_path | from json
}

def state-is-mounted [state_path: string] {
    let state = (schelk-state $state_path)
    ($state | get --optional is_mounted) == true
}

def actual-is-mounted [mount_point: string] {
    (mountpoint -q $mount_point | complete).exit_code == 0
}

def full-recover [state_path: string] {
    let marker = (clean-marker $state_path)
    rm -f $marker
    sudo schelk --state-path $state_path full-recover -y
    touch $marker
}

def cmd-detect [] {
    if (($env.SCHELK_STATE_PATH? | default "") != "") and (($env.SCHELK_MOUNT? | default "") != "") {
        print $"SCHELK_STATE_PATH=($env.SCHELK_STATE_PATH)"
        print $"SCHELK_MOUNT=($env.SCHELK_MOUNT)"
        return
    }

    if ("/var/lib/schelk/a.json" | path exists) {
        print "SCHELK_STATE_PATH=/var/lib/schelk/a.json"
        print "SCHELK_MOUNT=/reth-bench-a"
    } else {
        print "::error::No dual-schelk state file found"
        exit 1
    }
}

def cmd-restore [state_path: string, mount_point: string] {
    let marker = (clean-marker $state_path)

    print $"Restoring schelk snapshot \(($mount_point)\)..."
    if (state-is-mounted $state_path) or (actual-is-mounted $mount_point) {
        let result = (sudo schelk --state-path $state_path recover -y --kill | complete)
        if $result.stdout != "" { print $result.stdout }
        if $result.stderr != "" { print $result.stderr }
        if $result.exit_code == 0 {
            touch $marker
        } else {
            print $"Schelk recover failed for ($mount_point), falling back to full-recover..."
            full-recover $state_path
        }
    } else if ($marker | path exists) {
        print "Schelk volume is already clean and unmounted; skipping recovery."
    } else {
        print "Schelk volume is unmounted without a clean marker; running full-recover."
        full-recover $state_path
    }

    let mount_result = (sudo schelk --state-path $state_path mount | complete)
    if $mount_result.stdout != "" { print $mount_result.stdout }
    if $mount_result.stderr != "" { print $mount_result.stderr }
    if $mount_result.exit_code != 0 {
        print $"Schelk mount failed for ($mount_point), falling back to full-recover..."
        full-recover $state_path
        sudo schelk --state-path $state_path mount
    }

    sudo chown -R (whoami | str trim) $mount_point
}

def cmd-mark-dirty [state_path: string] {
    rm -f (clean-marker $state_path)
}

def cmd-cleanup [state_path: string] {
    let marker = (clean-marker $state_path)
    let result = (sudo schelk --state-path $state_path recover -y --kill | complete)
    if $result.stdout != "" { print $result.stdout }
    if $result.stderr != "" { print $result.stderr }
    if $result.exit_code == 0 {
        touch $marker
    } else {
        rm -f $marker
        exit $result.exit_code
    }
}

def cmd-promote [state_path: string] {
    sudo schelk --state-path $state_path promote -y --kill
    touch (clean-marker $state_path)
}

def usage [] {
    print "Usage:"
    print "  nu bench-schelk.nu detect"
    print "  nu bench-schelk.nu restore <state-path> <mount-point>"
    print "  nu bench-schelk.nu mark-dirty <state-path>"
    print "  nu bench-schelk.nu cleanup <state-path>"
    print "  nu bench-schelk.nu promote <state-path>"
}

def main [command?: string, arg1?: string, arg2?: string] {
    match $command {
        "detect" => { cmd-detect },
        "restore" => {
            if $arg1 == null or $arg2 == null {
                usage
                exit 2
            }
            cmd-restore $arg1 $arg2
        },
        "mark-dirty" => {
            if $arg1 == null {
                usage
                exit 2
            }
            cmd-mark-dirty $arg1
        },
        "cleanup" => {
            if $arg1 == null {
                usage
                exit 2
            }
            cmd-cleanup $arg1
        },
        "promote" => {
            if $arg1 == null {
                usage
                exit 2
            }
            cmd-promote $arg1
        },
        _ => {
            usage
            exit 2
        },
    }
}
