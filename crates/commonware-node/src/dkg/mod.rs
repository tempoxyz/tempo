pub mod ceremony;
pub mod manager;

#[derive(Debug, Clone, Copy)]
pub enum HardforkRegime {
    PreAllegretto,
    PostAllegretto,
}
