use config::{File, FileFormat};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "DEFAULT")]
    pub default: Option<DefaultSection>,

    pub identity: Option<IdentitySection>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DefaultSection {}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct IdentitySection {
    pub driver: Option<String>,
}

impl Config {
    pub fn new(path: PathBuf) -> Self {
        let builder =
            config::Config::builder().add_source(File::from(path).format(FileFormat::Ini));

        builder.build().unwrap().try_deserialize().unwrap()
    }
}
