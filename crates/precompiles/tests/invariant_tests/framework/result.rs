pub(crate) enum InvariantResult {
    Passed,
    Violated { message: String },
}
