use std::{
    collections::HashMap as Map,
    time::{
        Duration,
        Instant,
    },
};

use color_eyre::eyre::{
    Context,
    Result,
};
use rand::{
    rngs::SmallRng,
    Rng,
    SeedableRng,
};
use serde::{
    Deserialize,
    Serialize,
};
use tokio::process::Command;
use tracing::info;

#[derive(Debug)]
pub(crate) struct Fetcher {
    rng: SmallRng,
    last_fetch: Option<Instant>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PkgAudit {
    pub(crate) pkg_count: i64,
    pub(crate) packages: Option<Map<String, Package>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Package {
    pub(crate) version: String,
    pub(crate) issue_count: usize,
    pub(crate) issues: Vec<Issue>,

    #[serde(rename = "reverse dependencies")]
    pub(crate) reverse_dependencies: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Issue {
    #[serde(rename = "Affected versions")]
    pub(crate) affected_versions: Vec<String>,
    pub(crate) description: String,
    pub(crate) url: String,
}

impl Default for Fetcher {
    fn default() -> Self {
        Self {
            rng: SmallRng::from_rng(&mut rand::rng()),
            last_fetch: None,
        }
    }
}

impl Fetcher {
    pub(crate) async fn fetch(&mut self) -> Result<PkgAudit> {
        let fetch = if let Some(last_fetch) = self.last_fetch {
            let jitter = Duration::new(self.rng.random_range(0..100), 0);
            let minutes_30 = Duration::new(30 * 60, 0);
            let max_since = jitter + minutes_30;

            max_since < Instant::now().duration_since(last_fetch)
        } else {
            true
        };

        let output_audit = if fetch {
            info!("Fetching new audit database");

            self.last_fetch = Some(Instant::now());

            Command::new("pkg")
                .arg("audit")
                .arg("-F")
                .arg("-q")
                .arg("--raw=json-compact")
                .output()
                .await
                .context("failed to execute pkg audit")?
                .stdout
        } else {
            Command::new("pkg")
                .arg("audit")
                .arg("-q")
                .arg("--raw=json-compact")
                .output()
                .await
                .context("failed to execute pkg audit")?
                .stdout
        };

        let pkg_audit: PkgAudit =
            serde_json::from_slice(&output_audit).context("failed to deserialize pkg audit")?;

        Ok(pkg_audit)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn parse_example1() {
        const INPUT: &[u8] = include_bytes!("../resources/example1.json");

        let got: super::PkgAudit = serde_json::from_slice(INPUT).unwrap();

        assert_eq!(got.pkg_count, 1);
    }

    #[test]
    fn parse_example2() {
        const INPUT: &[u8] = include_bytes!("../resources/example2.json");

        let got: super::PkgAudit = serde_json::from_slice(INPUT).unwrap();

        assert_eq!(got.pkg_count, 15);
    }

    #[test]
    fn parse_example3() {
        const INPUT: &[u8] = include_bytes!("../resources/example3.json");

        let got: super::PkgAudit = serde_json::from_slice(INPUT).unwrap();

        assert_eq!(got.pkg_count, 0);
    }
}
