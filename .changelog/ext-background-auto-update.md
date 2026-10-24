---
tempo-ext: minor
---

Run extension auto-updates in a detached background process instead of on the invocation path, so `tempo <extension>` no longer waits on downloads or writes update messages to non-terminal stderr. Update notices are deferred to the next invocation whose stderr is a terminal, and `TEMPO_EXT_NO_AUTO_UPDATE=1` disables auto-update. Registry writes and installs are serialized with a file lock, and a background update never overrides a removal, pin, or install made while it was downloading.
