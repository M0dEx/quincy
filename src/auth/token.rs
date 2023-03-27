use chrono::{DateTime, Utc};
use getset::Getters;

#[derive(Getters)]
pub struct SessionToken {
    #[get = "pub"]
    value: String,
    #[get = "pub"]
    valid_until: DateTime<Utc>,
}
