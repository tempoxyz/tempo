use clap::ValueEnum;
use std::fmt;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum LogFormat {
    #[default]
    Terminal,
    LogFmt,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogFormat::Terminal => write!(f, "terminal"),
            LogFormat::LogFmt => write!(f, "log-fmt"),
        }
    }
}

pub fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::from_default_env();
    match format {
        LogFormat::LogFmt => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_logfmt::layer())
                .init();
        }
        LogFormat::Terminal => {
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(filter)
                .init();
        }
    }
}
