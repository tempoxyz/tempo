use crate::types::Height;
use commonware_storage::{
    metadata::{self, Metadata},
    Context,
};
use commonware_utils::sequence::U64;

/// The key used to store the last processed height in the metadata store.
const LATEST_KEY: U64 = U64::new(0xFF);

/// Last block acknowledged by the application.
#[derive(Clone, Copy)]
enum State {
    Unprocessed,
    Processed(Height),
}

impl State {
    const fn new(processed_height: Option<Height>) -> Self {
        match processed_height {
            Some(height) => Self::Processed(height),
            None => Self::Unprocessed,
        }
    }

    const fn processed_height(self) -> Option<Height> {
        match self {
            Self::Unprocessed => None,
            Self::Processed(height) => Some(height),
        }
    }

    const fn next_height(self) -> Height {
        match self {
            Self::Unprocessed => Height::zero(),
            Self::Processed(height) => height.next(),
        }
    }

    const fn acknowledge(&mut self, height: Height) {
        *self = Self::Processed(height);
    }
}

/// Application delivery stream progress and durable metadata.
pub(super) struct Stream<E: Context> {
    metadata: Metadata<E, U64, Height>,
    state: State,
}

impl<E: Context> Stream<E> {
    pub(super) async fn new(context: E, application_metadata_partition: &str) -> Self {
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition: application_metadata_partition.to_string(),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize application metadata");
        let state = State::new(metadata.get(&LATEST_KEY).copied());
        Self { metadata, state }
    }

    pub(super) const fn processed_height(&self) -> Option<Height> {
        self.state.processed_height()
    }

    pub(super) const fn next_height(&self) -> Height {
        self.state.next_height()
    }

    pub(super) fn acknowledge(&mut self, height: Height) {
        self.state.acknowledge(height);
        self.metadata.put(LATEST_KEY, height);
    }

    pub(super) async fn sync(&mut self) -> Result<(), metadata::Error> {
        self.metadata.sync().await
    }
}
