---
tempo-payload-builder: patch
---

The payload builder now removes a pool transaction from the pool when it fails execution, instead of only skipping it for the current build. It does so only when the build's parent is the pool's tip or descends from it, and runs the removal off the build path.
