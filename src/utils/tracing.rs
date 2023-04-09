use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

pub fn enable_tracing(log_level: &str) {
    let registry = tracing_subscriber::Registry::default();
    let fmt_layer = tracing_subscriber::fmt::Layer::new();
    let filter_layer = EnvFilter::try_new(log_level).unwrap();

    let subscriber = registry.with(filter_layer).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
