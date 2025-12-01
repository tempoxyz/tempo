pub(crate) mod ceremony;
pub(crate) mod manager;

#[derive(Debug, Clone, Copy)]
enum HardforkRegime {
    PreAllegretto,
    PostAllegretto,
}
