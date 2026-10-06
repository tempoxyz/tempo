"""Pure fake-machine tests. No host process, systemctl, sysctl or sysfs actions."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import producer_lifecycle as lifecycle


TOKEN = "1234567890abcdef"
CPU = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
THP = lifecycle.THP[0]


class FakeSystem:
    def __init__(self, config):
        self.config = config
        self.time = 100.0
        self.calls = []
        self.mutations = []
        self.units = {}
        self.cgroups = {}
        self.term_stops = True
        self.kill_stops = True
        self.bad_write = None
        self.on_signal = None
        self.files = {
            "/proc/sys/kernel/random/boot_id": "fake-boot\n",
            "/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n",
            "/proc/self/cgroup": "0::/outside.scope\n",
            lifecycle.SYSCTLS["net.ipv4.tcp_tw_reuse"]: "2\n",
            lifecycle.SYSCTLS["net.ipv4.ip_local_port_range"]: "32768\t60999\n",
            CPU: "powersave\n",
            lifecycle.TURBO[0]: "0\n",
            lifecycle.TURBO[1]: "1\n",
            THP + "/enabled": "[always] madvise never\n",
            THP + "/defrag": "always defer [madvise] never\n",
        }
        self.directories = {"/sys/fs/cgroup/cgroup.controllers", THP}
        self.services = {
            "cron.service": {"load": "loaded", "active": "active", "sub": "running"},
            "unattended-upgrades.service": {"load": "loaded", "active": "inactive", "sub": "dead"},
        }
        self.original_service_substate = {name: state["sub"] for name, state in self.services.items()}

    def now(self):
        return self.time

    def sleep(self, seconds):
        self.time += seconds

    def glob(self, pattern):
        assert pattern == lifecycle.GOVERNORS
        return sorted(p for p in self.files if p.endswith("/cpufreq/scaling_governor"))

    def exists(self, path):
        if path.startswith("/sys/fs/cgroup/system.slice/"):
            return path.rsplit("/", 1)[-1] in self.cgroups
        return path in self.files or path in self.directories

    def read(self, path, limit=16384):
        if path.endswith("/cgroup.events"):
            name = path.split("/")[-2]
            value = self.cgroups[name]
            return value if isinstance(value, str) else f"populated {int(value)}\nfrozen 0\n"
        return self.files[path]

    def add_unit(self, name, description=None, invocation="1" * 32):
        self.units[name] = {
            "Id": name, "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
            "Description": description or self.config["unit_description"],
            "ControlGroup": "/system.slice/" + name, "InvocationID": invocation,
        }
        self.cgroups[name] = True

    def tune(self):
        self.files[lifecycle.SYSCTLS["net.ipv4.tcp_tw_reuse"]] = "1\n"
        self.files[lifecycle.SYSCTLS["net.ipv4.ip_local_port_range"]] = "1024 65535\n"
        self.files[CPU] = "performance\n"
        self.files[lifecycle.TURBO[0]] = "1\n"
        self.files[lifecycle.TURBO[1]] = "0\n"
        self.files[THP + "/enabled"] = "always madvise [never]\n"
        self.files[THP + "/defrag"] = "always madvise [never]\n"
        for state in self.services.values():
            if state["load"] == "loaded":
                state.update(active="inactive", sub="dead")

    def command(self, argv, timeout, stdin=None):
        assert 0 < timeout <= lifecycle.COMMAND_SECONDS
        self.time += 0.001
        self.calls.append((list(argv), timeout, stdin))
        result = {"code": 0, "stdout": "", "stderr": ""}
        if argv[:2] == ["systemctl", "show"]:
            assert "--all" in argv  # Empty identity/cgroup fields must be retained.
            name = argv[2]
            if name in self.services:
                state = self.services[name]
                item = dict(Id=name, LoadState=state["load"], ActiveState=state["active"],
                            SubState=state["sub"], ControlGroup="", Description=name, InvocationID="")
            else:
                item = self.units.get(name, dict(Id=name, LoadState="not-found", ActiveState="inactive",
                                                SubState="dead", ControlGroup="", Description="", InvocationID=""))
            result["code"] = 4 if item["LoadState"] == "not-found" else 0
            result["stdout"] = "\n".join(f"{k}={item[k]}" for k in lifecycle.PROPERTIES) + "\n"
            return result
        assert argv[:3] == ["sudo", "-n", "--"]
        # Every machine mutation must follow the durable prestate and intent.
        directory = Path(self.config["state_dir"])
        prestate = json.loads((directory / "prestate.json").read_text())
        journal = json.loads((directory / "journal.json").read_text())
        assert journal["prestate_sha256"] == lifecycle.digest(lifecycle.encoded(prestate))
        assert journal["events"][-1]["kind"] == "command_intent"
        assert journal["events"][-1]["argv"] == argv
        self.mutations.append(list(argv))
        command = argv[3:]
        if command[:2] == ["systemctl", "kill"]:
            assert command[2] == "--kill-whom=all"
            sig, name = command[3].split("=", 1)[1], command[4]
            assert name in [self.config["control_unit"], *self.config["node_units"]]
            if self.on_signal:
                self.on_signal(sig, name, self)
            if (sig == "TERM" and self.term_stops) or (sig == "KILL" and self.kill_stops):
                self.cgroups[name] = False
                self.units[name].update(ActiveState="inactive", SubState="dead")
        elif command[:2] == ["sysctl", "-w"]:
            key, value = command[2].split("=", 1)
            path = lifecycle.SYSCTLS[key]
            if path != self.bad_write:
                self.files[path] = value + "\n"
        elif command[0] == "tee":
            path = command[1]
            if path != self.bad_write:
                value = stdin.decode().strip()
                self.files[path] = f"[{value}] always madvise never\n" if path.startswith(THP) else value + "\n"
        elif command[0] == "systemctl" and command[1] in ("start", "stop"):
            name = command[2]
            active = command[1] == "start"
            sub = self.original_service_substate[name] if active else "dead"
            self.services[name].update(active="active" if active else "inactive", sub=sub)
        else:
            raise AssertionError(f"unexpected fake command {argv!r}")
        return result


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        prefix = "tempo-producer-" + TOKEN
        self.config = dict(schema_version=1, run_token=TOKEN, state_dir=self.temporary.name,
                           control_unit=prefix + "-control.scope",
                           node_units=[prefix + "-a.scope", prefix + "-b.scope"],
                           unit_description="tempo-producer:" + TOKEN)
        self.machine = FakeSystem(self.config)

    def helper(self):
        return lifecycle.Lifecycle(self.config, self.machine)

    def capture(self):
        return self.helper().capture()

    def journal(self):
        return json.loads((Path(self.temporary.name) / "journal.json").read_text())

    def update_journal(self, **changes):
        value = self.journal()
        value.update(changes)
        lifecycle.atomic_json(Path(self.temporary.name) / "journal.json", value)

    def units_live(self):
        for name in [self.config["control_unit"], *self.config["node_units"]]:
            self.machine.add_unit(name)

    def enter_control(self):
        self.machine.add_unit(self.config["control_unit"])
        self.machine.files["/proc/self/cgroup"] = "0::/system.slice/" + self.config["control_unit"] + "\n"

    def test_capture_durable_before_any_mutation_and_never_overwritten(self):
        result = self.capture()
        path = Path(self.temporary.name) / "prestate.json"
        original = path.read_bytes()
        self.assertEqual(result["status"], "captured")
        self.assertEqual(self.machine.mutations, [])
        with self.assertRaisesRegex(lifecycle.Refusal, "already captured"):
            self.capture()
        self.assertEqual(path.read_bytes(), original)

    def test_full_restoration_matches_all_original_settings(self):
        before = self.helper().settings()
        self.capture()
        self.machine.tune()
        self.units_live()
        result = self.helper().restore()
        self.assertEqual(result["status"], "restored")
        self.assertEqual(self.helper().settings(), before)
        self.assertEqual(self.journal()["status"], "restored")
        self.assertTrue(all(not value for value in self.machine.cgroups.values()))

    def test_active_swap_refused_before_any_persisted_permission(self):
        self.machine.files["/proc/swaps"] += "/swapfile file 123 0 -2\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "active swap"):
            self.capture()
        self.assertFalse((Path(self.temporary.name) / "prestate.json").exists())
        self.assertEqual(self.machine.mutations, [])

    def test_failed_and_transitional_services_refused(self):
        for active, sub in (("failed", "failed"), ("activating", "start"), ("deactivating", "stop-sigterm")):
            with self.subTest(active=active):
                self.machine.services["cron.service"].update(active=active, sub=sub)
                with self.assertRaisesRegex(lifecycle.Refusal, "failed/transitional"):
                    self.capture()
                self.assertEqual(self.machine.mutations, [])

    def test_active_exited_service_is_stable_and_restored_exactly(self):
        self.machine.services["cron.service"]["sub"] = "exited"
        self.machine.original_service_substate["cron.service"] = "exited"
        self.capture()
        self.machine.tune()
        self.helper().restore()
        self.assertEqual(self.machine.services["cron.service"]["sub"], "exited")

    def test_absent_service_stays_absent(self):
        self.machine.services["cron.service"] = {"load": "not-found", "active": "inactive", "sub": "dead"}
        self.capture()
        self.machine.tune()
        self.helper().restore()
        self.assertFalse(any("cron.service" in command for command in self.machine.mutations))

    def test_existing_unit_refused_at_capture(self):
        self.machine.add_unit(self.config["node_units"][0])
        with self.assertRaisesRegex(lifecycle.Refusal, "already exists"):
            self.capture()
        self.assertEqual(self.machine.mutations, [])

    def test_existing_even_empty_cgroup_refused_at_capture(self):
        self.machine.cgroups[self.config["node_units"][0]] = False
        with self.assertRaisesRegex(lifecycle.Refusal, "cgroup already exists"):
            self.capture()

    def test_foreign_description_never_signalled(self):
        self.capture()
        self.machine.add_unit(self.config["control_unit"], description="some other run")
        with self.assertRaisesRegex(lifecycle.Refusal, "Description mismatch"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])
        self.assertEqual(self.journal()["status"], "restore_failed")

    def test_control_stops_first_including_node_created_during_term(self):
        self.capture()
        control = self.config["control_unit"]
        self.machine.add_unit(control)

        def spawn_before_exit(sig, name, machine):
            if name == control:
                self.assertEqual(self.journal()["status"], "closing")
                machine.add_unit(self.config["node_units"][1])

        self.machine.on_signal = spawn_before_exit
        self.helper().restore()
        kills = [command[-1] for command in self.machine.mutations if "kill" in command]
        self.assertEqual(kills, [control, self.config["node_units"][1]])

    def test_kill_after_bounded_term_wait(self):
        self.capture()
        self.machine.add_unit(self.config["node_units"][0])
        self.machine.term_stops = False
        begin = self.machine.now()
        self.helper().restore()
        signals = [command[-2] for command in self.machine.mutations if "kill" in command]
        self.assertEqual(signals, ["--signal=TERM", "--signal=KILL"])
        self.assertGreaterEqual(self.machine.now() - begin, lifecycle.TERM_SECONDS)
        self.assertLess(self.machine.now() - begin, lifecycle.TERM_SECONDS + 3)

    def test_unstoppable_node_forbids_settings_restore(self):
        self.capture()
        self.machine.tune()
        self.machine.add_unit(self.config["node_units"][0])
        self.machine.term_stops = self.machine.kill_stops = False
        with self.assertRaisesRegex(lifecycle.Refusal, "remain after TERM/KILL"):
            self.helper().restore()
        self.assertTrue(all("kill" in command for command in self.machine.mutations))
        self.assertEqual(self.machine.files[CPU], "performance\n")
        self.assertEqual(self.journal()["status"], "restore_failed")

    def test_unrelated_scope_never_touched(self):
        self.capture()
        self.machine.add_unit("unrelated.scope", description="unrelated")
        self.helper().restore()
        self.assertTrue(self.machine.cgroups["unrelated.scope"])
        self.assertFalse(any("unrelated.scope" in command for command in self.machine.mutations))

    def test_invocation_identity_change_refused(self):
        self.capture()
        name = self.config["node_units"][0]
        self.machine.add_unit(name)
        self.enter_control()
        self.helper().quiesce()
        self.machine.files["/proc/self/cgroup"] = "0::/outside.scope\n"
        self.machine.add_unit(name, invocation="2" * 32)
        before = len(self.machine.mutations)
        with self.assertRaisesRegex(lifecycle.Refusal, "InvocationID changed"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations[before:][0][-1], self.config["control_unit"])
        self.assertTrue(all(command[-1] != name for command in self.machine.mutations[before:]))

    def test_missing_cgroup_population_is_fail_closed(self):
        self.capture()
        name = self.config["node_units"][0]
        self.machine.add_unit(name)
        self.enter_control()
        self.machine.cgroups[name] = "frozen 0\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "populated"):
            self.helper().quiesce()
        self.assertEqual(self.machine.mutations, [])

    def test_populated_cgroup_without_owned_unit_is_refused(self):
        self.capture()
        self.machine.cgroups[self.config["node_units"][0]] = True
        with self.assertRaisesRegex(lifecycle.Refusal, "no owned systemd unit"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])

    def test_quiesce_preserves_control_scope_and_tuned_settings(self):
        self.capture()
        self.units_live()
        self.machine.tune()
        self.machine.files["/proc/self/cgroup"] = "0::/system.slice/" + self.config["control_unit"] + "\n"
        result = self.helper().quiesce()
        self.assertTrue(result["snapshot_restore_permitted"])
        self.assertTrue(self.machine.cgroups[self.config["control_unit"]])
        self.assertEqual(self.machine.files[CPU], "performance\n")
        self.assertEqual(self.journal()["status"], "captured")

    def test_quiesce_outside_control_scope_refused(self):
        self.capture()
        with self.assertRaisesRegex(lifecycle.Refusal, "caller must belong"):
            self.helper().quiesce()
        self.assertEqual(self.machine.mutations, [])

    def test_quiesce_control_ownership_must_match(self):
        self.capture()
        self.enter_control()
        self.machine.units[self.config["control_unit"]]["Description"] = "foreign"
        with self.assertRaisesRegex(lifecycle.Refusal, "Description mismatch"):
            self.helper().quiesce()
        self.assertEqual(self.machine.mutations, [])

    def test_closing_blocks_late_launch_before_any_mutation(self):
        self.capture()
        for status in ("closing", "restore_failed", "restored"):
            self.update_journal(status=status)
            with self.assertRaisesRegex(lifecycle.Refusal, "closing/closed"):
                self.helper().quiesce()
        self.assertEqual(self.machine.mutations, [])

    def test_restore_idempotent_and_original_prestate_preserved(self):
        self.capture()
        path = Path(self.temporary.name) / "prestate.json"
        before = path.read_bytes()
        self.machine.tune()
        self.helper().restore()
        count = len(self.machine.mutations)
        self.helper().restore()
        self.assertEqual(len(self.machine.mutations), count)
        self.assertEqual(path.read_bytes(), before)

    def test_changed_boot_refused_without_actions(self):
        self.capture()
        self.machine.files["/proc/sys/kernel/random/boot_id"] = "new-boot\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "boot changed"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])

    def test_changed_config_refused_without_actions(self):
        self.capture()
        altered = copy.deepcopy(self.config)
        altered["run_token"] = "f" * 16
        altered["control_unit"] = "tempo-producer-" + "f" * 16 + "-control.scope"
        altered["node_units"] = ["tempo-producer-" + "f" * 16 + f"-{role}.scope" for role in ("a", "b")]
        altered["unit_description"] = "tempo-producer:" + "f" * 16
        with self.assertRaisesRegex(lifecycle.Refusal, "config changed"):
            lifecycle.Lifecycle(altered, self.machine).restore()
        self.assertEqual(self.machine.mutations, [])

    def test_modified_prestate_refused_without_actions(self):
        self.capture()
        path = Path(self.temporary.name) / "prestate.json"
        value = json.loads(path.read_text())
        value["settings"]["sysctls"]["net.ipv4.tcp_tw_reuse"] = "0"
        lifecycle.atomic_json(path, value)
        with self.assertRaisesRegex(lifecycle.Refusal, "prestate changed"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])

    def test_helper_source_identity_refused(self):
        self.capture()
        helper = self.helper()
        helper.source_sha = "bad"
        with self.assertRaisesRegex(lifecycle.Refusal, "helper source changed"):
            helper.restore()

    def test_sysfs_path_set_change_refused(self):
        self.capture()
        self.machine.files[CPU.replace("cpu0", "cpu1")] = "powersave\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "sysfs path set changed"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])

    def test_changed_setting_topology_does_not_prevent_owned_process_stop(self):
        self.capture()
        self.units_live()
        self.machine.files[CPU.replace("cpu0", "cpu1")] = "powersave\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "sysfs path set changed"):
            self.helper().restore()
        self.assertTrue(all(not value for value in self.machine.cgroups.values()))
        self.assertTrue(all("kill" in command for command in self.machine.mutations))

    def test_zero_exit_without_effect_is_not_restored(self):
        self.capture()
        self.machine.tune()
        self.machine.bad_write = CPU
        with self.assertRaisesRegex(lifecycle.Refusal, "sysfs verification failed"):
            self.helper().restore()
        self.assertEqual(self.journal()["status"], "restore_failed")
        self.machine.bad_write = None
        self.helper().restore()
        self.assertEqual(self.journal()["status"], "restored")

    def test_self_scope_restore_refused(self):
        self.capture()
        self.machine.files["/proc/self/cgroup"] = "0::/system.slice/" + self.config["control_unit"] + "\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "own scope"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])

    def test_new_swap_not_silently_disabled(self):
        self.capture()
        self.machine.files["/proc/swaps"] += "/new-swap file 123 0 -2\n"
        with self.assertRaisesRegex(lifecycle.Refusal, "active swap"):
            self.helper().restore()
        self.assertEqual(self.machine.mutations, [])

    def test_operation_deadline_prevents_next_command(self):
        self.capture()
        helper = self.helper()
        helper.deadline = self.machine.now() - 1
        with self.assertRaisesRegex(lifecycle.Refusal, "deadline"):
            helper.restore()
        self.assertEqual(self.machine.mutations, [])

    def test_leftover_atomic_temporary_does_not_block_recovery(self):
        self.capture()
        (Path(self.temporary.name) / "journal.json.tmp-crash").write_text("partial")
        self.machine.tune()
        self.helper().restore()
        self.assertEqual(self.journal()["status"], "restored")

    def test_thp_selection_requires_one_bracketed_value(self):
        self.assertEqual(lifecycle.selected_value("always [madvise] never\n"), "madvise")
        for raw in ("always madvise never", "[always] [never]", "[bad/value]"):
            with self.assertRaises(lifecycle.Refusal):
                lifecycle.selected_value(raw)

    def test_config_rejects_unowned_names_and_snapshot_journal(self):
        for patch in ({"node_units": ["tempo-e2e-a.scope", "tempo-e2e-b.scope"]},
                      {"state_dir": "/var/lib/schelk/journal"},
                      {"control_unit": "unrelated.scope"},
                      {"unexpected": True}):
            with self.subTest(patch=patch), self.assertRaises(lifecycle.Refusal):
                lifecycle.validate_config({**self.config, **patch})


class CommandOwnershipTests(unittest.TestCase):
    """Mocked kernel/process APIs only; no subprocess is created by these tests."""

    def command_fixture(self, mode, wait_error=False, ownership_lost=False):
        events = []
        clock = [100.0]

        class Stream:
            def __init__(self, fd):
                self.fd = fd

            def fileno(self):
                return self.fd

            def close(self):
                pass

        class Process:
            pid = 424242
            stdout = Stream(900)
            stderr = Stream(901)
            owner = "original"

            def poll(self):
                # This models the original bug: poll reaps an exited leader,
                # permitting an unrelated process to acquire the same PGID.
                self.owner = "unrelated_reused_pgid"
                events.append("poll_reaped")
                return 0

            def wait(self, timeout):
                self.owner = "unrelated_reused_pgid"
                events.append("reaped")
                if wait_error:
                    raise RuntimeError("injected exception after reap")
                return 0

        process = Process()

        class Selector:
            def __init__(self):
                self.entries = {}

            def register(self, stream, event, label):
                self.entries[stream] = SimpleNamespace(fileobj=stream, data=label)

            def unregister(self, stream):
                del self.entries[stream]

            def get_map(self):
                return self.entries

            def select(self, timeout):
                clock[0] += min(timeout, 0.1)
                if mode == "held_pipe":
                    return []
                if mode == "overflow":
                    return [(next(iter(self.entries.values())), 1)]
                return [(key, 1) for key in self.entries.values()]

            def close(self):
                self.entries.clear()

        def observe(kind, pid, flags):
            self.assertEqual((kind, pid), (lifecycle.os.P_PID, process.pid))
            self.assertTrue(flags & lifecycle.os.WNOWAIT)
            if ownership_lost:
                process.owner = "unrelated_reused_pgid"
                raise ChildProcessError("injected unexpected external reap")
            self.assertEqual(process.owner, "original")
            return SimpleNamespace(si_pid=pid, si_status=0)

        def group_signal(pid, sig):
            events.append(("signal", process.owner, pid, sig))
            self.assertEqual(process.owner, "original", "must never signal a group after releasing leader ownership")

        system = lifecycle.System()
        system.now = lambda: clock[0]
        patches = (
            mock.patch.object(lifecycle.subprocess, "Popen", return_value=process),
            mock.patch.object(lifecycle.selectors, "DefaultSelector", side_effect=Selector),
            mock.patch.object(lifecycle.os, "set_blocking"),
            mock.patch.object(lifecycle.os, "waitid", side_effect=observe),
            mock.patch.object(lifecycle.os, "killpg", side_effect=group_signal),
            mock.patch.object(lifecycle.os, "read", side_effect=lambda fd, count: b"x" * count if mode == "overflow" else b""),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return system, events

    def test_exited_leader_with_held_pipe_stays_owned_until_timeout_signal(self):
        system, events = self.command_fixture("held_pipe")
        with self.assertRaisesRegex(lifecycle.Refusal, "timeout"):
            system.command(["fake"], timeout=1)
        self.assertEqual([x[0] if isinstance(x, tuple) else x for x in events], ["signal", "reaped"])

    def test_output_limit_signals_only_before_reap(self):
        system, events = self.command_fixture("overflow")
        with self.assertRaisesRegex(lifecycle.Refusal, "output limit"):
            system.command(["fake"], timeout=2)
        self.assertEqual([x[0] if isinstance(x, tuple) else x for x in events], ["signal", "reaped"])

    def test_normal_completion_closes_signals_before_reap(self):
        system, events = self.command_fixture("eof")
        self.assertEqual(system.command(["fake"], timeout=1)["code"], 0)
        self.assertEqual(events, ["reaped"])

    def test_exception_after_reap_cannot_signal_recycled_group(self):
        system, events = self.command_fixture("eof", wait_error=True)
        with self.assertRaisesRegex(RuntimeError, "after reap"):
            system.command(["fake"], timeout=1)
        self.assertEqual(events, ["reaped"])

    def test_lost_leader_ownership_refuses_group_signal(self):
        system, events = self.command_fixture("held_pipe", ownership_lost=True)
        with self.assertRaisesRegex(lifecycle.Refusal, "ownership lost"):
            system.command(["fake"], timeout=1)
        self.assertEqual(events, [])

    def test_permission_failure_is_not_absent_cgroup(self):
        system = lifecycle.System()
        with mock.patch.object(lifecycle.os, "stat", side_effect=PermissionError("unreadable")):
            with self.assertRaises(PermissionError):
                system.exists("/fake/cgroup")
        with mock.patch.object(lifecycle.os, "stat", side_effect=FileNotFoundError("absent")):
            self.assertFalse(system.exists("/fake/cgroup"))

    def test_selector_allocation_failure_cannot_launch_child(self):
        with mock.patch.object(lifecycle.selectors, "DefaultSelector", side_effect=OSError("selector allocation")), \
                mock.patch.object(lifecycle.subprocess, "Popen") as launch, \
                mock.patch.object(lifecycle.os, "killpg") as signal_group:
            with self.assertRaisesRegex(OSError, "selector allocation"):
                lifecycle.System().command(["fake"], timeout=1)
        launch.assert_not_called()
        signal_group.assert_not_called()

    def test_launch_failure_closes_preallocated_selector_without_signalling(self):
        selector = mock.Mock()
        with mock.patch.object(lifecycle.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(lifecycle.subprocess, "Popen", side_effect=OSError("spawn failed")), \
                mock.patch.object(lifecycle.os, "killpg") as signal_group:
            with self.assertRaisesRegex(OSError, "spawn failed"):
                lifecycle.System().command(["fake"], timeout=1)
        selector.close.assert_called_once_with()
        signal_group.assert_not_called()

    def test_governor_directory_open_permission_error_is_not_empty_list(self):
        with mock.patch.object(lifecycle.os, "scandir", side_effect=PermissionError("CPU tree unreadable")):
            with self.assertRaisesRegex(PermissionError, "CPU tree unreadable"):
                lifecycle.System().glob(lifecycle.GOVERNORS)

    def test_governor_iteration_error_does_not_return_partial_prestate(self):
        def entries():
            yield SimpleNamespace(name="cpu0")
            raise OSError("CPU enumeration interrupted")

        with mock.patch.object(lifecycle.os, "scandir") as scan, \
                mock.patch.object(lifecycle.os, "stat", return_value=SimpleNamespace()):
            scan.return_value.__enter__.return_value = entries()
            with self.assertRaisesRegex(OSError, "enumeration interrupted"):
                lifecycle.System().glob(lifecycle.GOVERNORS)

    def test_governor_candidate_permission_error_is_not_omitted(self):
        with mock.patch.object(lifecycle.os, "scandir") as scan, \
                mock.patch.object(lifecycle.os, "stat", side_effect=PermissionError("governor unreadable")):
            scan.return_value.__enter__.return_value = iter([SimpleNamespace(name="cpu0")])
            with self.assertRaisesRegex(PermissionError, "governor unreadable"):
                lifecycle.System().glob(lifecycle.GOVERNORS)

    def test_governor_enumeration_accepts_only_existing_cpu_number_paths(self):
        def candidate_stat(path):
            if "/cpu2/" in path:
                raise FileNotFoundError("CPU2 has no cpufreq governor")
            return SimpleNamespace()

        with mock.patch.object(lifecycle.os, "scandir") as scan, \
                mock.patch.object(lifecycle.os, "stat", side_effect=candidate_stat):
            scan.return_value.__enter__.return_value = iter([
                SimpleNamespace(name=name) for name in ("cpuidle", "cpu2", "cpu1", "cpu0", "cpufreq")
            ])
            found = lifecycle.System().glob(lifecycle.GOVERNORS)
        self.assertEqual(found, [CPU, CPU.replace("cpu0", "cpu1")])


if __name__ == "__main__":
    unittest.main()
