minimal deps for foundry. 

storage ops, can we leverage sol macro, etc. 

diff from evm

structure
- one for crate for contract bindings
- maybe evm and precompieles


- storage provider stuff, tons of wrapping, is there a way we can do this and not perfrom a bunch of redundant lookups

- yeah we always load/touch/etc. 


- reading from storage/writing, the way it works right now with 
  - read store, delete, update, specifically for mappings/arrays etc. easy to just focus on dev work
