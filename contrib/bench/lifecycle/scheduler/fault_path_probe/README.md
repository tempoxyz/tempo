# Private file-backed fault-path probe

This synthetic-only experiment refines the observed kernel IO category when a
complete, resolved leaf-to-root stack has exact `filemap_fault` ancestry above
`io_schedule` or `io_schedule_timeout`. All old conflicting, unresolved, empty
and truncated outcomes remain unknown. A missing, differently named or wrongly
ordered ancestor leaves generic kernel IO; `filemap_fault` alone proves no IO
wait. The experimental numeric code6 means `filemap_fault_io_schedule`.

Linux's [filemap_fault implementation](https://github.com/torvalds/linux/blob/v6.8/mm/filemap.c)
handles mapped-file faults and may wait for a folio. The observed ancestry does
not prove a physical read, a particular file/state page, a faulting instruction,
a major fault, a device, or persistence work. Concurrent folio activity may also
cause that path to wait. Its semantic claim is deliberately the kernel callpath.

Run pure fixtures:

```
python3 -m unittest discover -s contrib/bench/lifecycle/scheduler/fault_path_probe -q
```

Run the optional local positive/negative-control probe using an explicit owned
scratch directory (never a node/datadir/snapshot):

```
sudo -n env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
  contrib/bench/lifecycle/scheduler/fault_path_probe/probe.py OWNED_SCRATCH
```

The helper creates and fsyncs one32MiB private tempfile. Two sequential registered
threads each read it twice: mmap with MADV_RANDOM, then ordinary pread. Only
POSIX_FADV_DONTNEED on that owned file is used; there is no global cache drop,
mount/sysctl change or access to existing application files. Map/read addresses,
native identities and symbols stay private. The child is stopped before attach,
has parent-death protection and a30-second deadline, and is reaped before owned
temporary files are removed. Inherited stdout contains only two numeric fault
counts. No node is launched.

The bounded immutable stack map and sample counters preserve exact positive
ancestry through classification, with kernel depth-limit/truncation checks,
closed statuses and probe-miss checks. An empty/partial attach does not pass:
both roles must register once and produce samples; the mmap role must show
positive code6 and measured major faults; the read control must show positive
generic IO and zero code6. That control supports discrimination in this fixture,
not proof that every read operation on every kernel lacks fault ancestry.

The first local run observed16,384 mmap code6 samples and16,384 major faults;
the read control observed16,378 generic IO samples, three unmatched samples and
zero code6/major faults. Stack/map/registration/probe-miss counts were zero.
These are feasibility counts, not performance measurements or validator evidence.
Production capture currently remains unchanged. Old schema4 stacks were discarded
privately; their generic IO intervals cannot be retrospectively subdivided.
