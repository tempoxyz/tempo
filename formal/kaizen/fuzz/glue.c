// C glue between the Rust fuzzer and the Lean-compiled follower core (copied from shim/glue.c,
// extended with the stateRoot argument of kz_step and kz_tip_state_root).
// lean.h's object helpers are static inline, so Rust calls these wrappers.
#include <lean/lean.h>
#include <string.h>

void lean_initialize_runtime_module(void);

extern lean_object* KZ_INIT_FN(uint8_t builtin);
extern lean_object* kz_new(uint64_t epoch_length, uint64_t from_epoch, lean_object* network_key);
extern lean_object* kz_step(lean_object* s, uint64_t height, lean_object* block_digest,
                            lean_object* parent_digest, lean_object* state_root, lean_object* cert,
                            uint8_t has_dkg, uint64_t dkg_epoch, lean_object* dkg_key);
extern lean_object* kz_out_state(lean_object* o);
extern uint8_t kz_out_code(lean_object* o);
extern uint64_t kz_tip_height(lean_object* s);
extern uint8_t kz_has_tip(lean_object* s);
extern lean_object* kz_tip_digest(lean_object* s);
extern lean_object* kz_tip_state_root(lean_object* s);

int kzg_init(void) {
  lean_initialize_runtime_module();
  lean_object* res = KZ_INIT_FN(1);
  if (!lean_io_result_is_ok(res)) { lean_io_result_show_error(res); lean_dec_ref(res); return 1; }
  lean_dec_ref(res);
  lean_io_mark_end_initialization();
  return 0;
}

lean_object* kzg_bytes(const uint8_t* p, size_t n) {
  lean_object* a = lean_alloc_sarray(1, n, n);
  if (n) memcpy(lean_sarray_cptr(a), p, n);
  return a;
}
const uint8_t* kzg_bytes_ptr(lean_object* a) { return lean_sarray_cptr(a); }
size_t kzg_bytes_len(lean_object* a) { return lean_sarray_size(a); }
void kzg_dec(lean_object* o) { lean_dec(o); }

lean_object* kzg_new(uint64_t epoch_length, uint64_t from_epoch, const uint8_t* key, size_t key_len) {
  return kz_new(epoch_length, from_epoch, kzg_bytes(key, key_len));
}

// Consumes *state, replaces it with the next state, returns the result code.
// Unlike the shim, digest/parent/stateRoot lengths are explicit so the fuzzer can vary them.
uint8_t kzg_step(lean_object** state, uint64_t height, const uint8_t* digest, size_t digest_len,
                 const uint8_t* parent, size_t parent_len, const uint8_t* state_root,
                 size_t state_root_len, const uint8_t* cert, size_t cert_len, uint8_t has_dkg,
                 uint64_t dkg_epoch, const uint8_t* dkg_key, size_t dkg_key_len) {
  lean_object* out = kz_step(*state, height, kzg_bytes(digest, digest_len),
                             kzg_bytes(parent, parent_len), kzg_bytes(state_root, state_root_len),
                             kzg_bytes(cert, cert_len), has_dkg, dkg_epoch,
                             kzg_bytes(dkg_key, dkg_key_len));
  lean_inc(out);
  uint8_t code = kz_out_code(out);
  *state = kz_out_state(out);
  return code;
}

uint64_t kzg_tip_height(lean_object* s) { lean_inc(s); return kz_tip_height(s); }
uint8_t kzg_has_tip(lean_object* s) { lean_inc(s); return kz_has_tip(s); }
// Owned ByteArray results: the caller copies them and calls kzg_dec.
lean_object* kzg_tip_digest(lean_object* s) { lean_inc(s); return kz_tip_digest(s); }
lean_object* kzg_tip_state_root(lean_object* s) { lean_inc(s); return kz_tip_state_root(s); }
