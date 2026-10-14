use std::{
    collections::HashMap,
    process::Command,
    time::{
        Duration,
        Instant,
    },
};

use itertools::Itertools;
use metrics::{
    describe_gauge,
    gauge,
};
use rand::{
    RngExt,
    rngs::ThreadRng,
};
use thiserror::Error;
use tracing::info;

use crate::pkg_audit::PkgAudit;

#[derive(Debug, Error)]
pub enum Error {
    #[error("can not deserialize pkg audit output: {0}")]
    DeserializePkgAudit(serde_json::Error),

    #[error("can not convert reverse depency length: {0}")]
    ConvertReverseDependenciesLenght(std::num::TryFromIntError),

    #[error("can not convert installed packages count: {0}")]
    ConvertPackagesInstalled(std::num::TryFromIntError),
}

// TODO: Add metric for total amount of packages installed
#[derive(Debug)]
pub struct MetricExporter {
    rng: ThreadRng,
    last_fetch: Option<std::time::Instant>,
}

impl MetricExporter {
    pub fn new() -> Self {
        describe_gauge!(
            "pkg_audit_exporter_packages_installed",
            "how many packages are installed"
        );
        describe_gauge!(
            "pkg_audit_exporter_vulnerable_packages_total",
            "how many packages are installed"
        );
        describe_gauge!(
            "pkg_audit_exporter_problems_found",
            "how many problems where found"
        );
        describe_gauge!(
            "pkg_audit_exporter_vulnerable_packages",
            "which packages are vunerable"
        );
        describe_gauge!(
            "pkg_audit_exporter_vulnerable_reverse_packages",
            "which packages are depending on vunerable packages"
        );
        describe_gauge!(
            "pkg_audit_exporter_dependent_packages",
            "how many packages are depending on this vunerable package"
        );

        Self {
            rng: rand::rng(),
            last_fetch: None,
        }
    }

    pub fn update(&mut self) -> Result<(), Error> {
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
                .expect("failed to execute pkg audit")
                .stdout
        } else {
            Command::new("pkg")
                .arg("audit")
                .arg("-q")
                .arg("--raw=json-compact")
                .output()
                .expect("failed to execute pkg audit")
                .stdout
        };

        let pkg_audit: PkgAudit =
            serde_json::from_slice(&output_audit).map_err(Error::DeserializePkgAudit)?;

        update_metrics(pkg_audit)
    }
}

/// Labeled series that are not set again are removed by the exporter's idle
/// timeout, so packages that are no longer vulnerable disappear on their own.
fn update_metrics(pkg_audit: PkgAudit) -> Result<(), Error> {
    let packages_installed: u32 = {
        let output = Command::new("pkg")
            .arg("info")
            .output()
            .expect("failed to execute pkg info")
            .stdout;

        String::from_utf8_lossy(&output)
            .lines()
            .count()
            .try_into()
            .map_err(Error::ConvertPackagesInstalled)?
    };

    gauge!("pkg_audit_exporter_packages_installed").set(packages_installed);

    gauge!("pkg_audit_exporter_vulnerable_packages_total").set(pkg_audit.pkg_count);
    let packages = pkg_audit.packages.unwrap_or_default();

    let mut problems_found = 0;
    let mut vulnerable_reverse_packages: HashMap<String, u32> = HashMap::new();

    for (name, package) in packages {
        let dependent_packages: u32 = package
            .reverse_dependencies
            .len()
            .try_into()
            .map_err(Error::ConvertReverseDependenciesLenght)?;

        problems_found += package.issue_count + dependent_packages;

        gauge!(
            "pkg_audit_exporter_vulnerable_packages",
            "name" => name.clone(),
            "version" => package.version,
            "urls" => package.issues.iter().map(|issue| &issue.url).join(","),
        )
        .set(package.issue_count);

        gauge!("pkg_audit_exporter_dependent_packages", "name" => name).set(dependent_packages);

        for package in package.reverse_dependencies {
            *vulnerable_reverse_packages.entry(package).or_default() += 1;
        }
    }

    gauge!("pkg_audit_exporter_problems_found").set(problems_found);

    for (name, count) in vulnerable_reverse_packages {
        gauge!("pkg_audit_exporter_vulnerable_reverse_packages", "name" => name).set(count);
    }

    Ok(())
}
