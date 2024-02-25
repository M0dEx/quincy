use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

/// Returns a new `tracing` subscriber with the specified log level.
///
/// ### Arguments
/// - `log_level` - the log level to use
pub fn log_subscriber(log_level: &str) -> impl Subscriber {
    let registry = tracing_subscriber::Registry::default();
    let fmt_layer = tracing_subscriber::fmt::Layer::new();
    let filter_layer = EnvFilter::try_new(log_level).unwrap();

    registry.with(filter_layer).with(fmt_layer)
}
