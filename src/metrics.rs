use std::{
    convert::TryInto,
    process::Command,
    time::{
        Duration,
        Instant,
    },
};

use log::info;
use prometheus_exporter::prometheus::{
    register_int_gauge,
    register_int_gauge_vec,
    IntGauge,
    IntGaugeVec,
};
use rand::{
    prelude::ThreadRng,
    Rng,
};
use thiserror::Error;

use crate::pkg_audit::PkgAudit;

#[derive(Debug, Error)]
pub enum Error {
    #[error("can not deserialize pkg audit output: {0}")]
    DeserializePkgAudit(serde_json::Error),

    #[error("can not convert reverse depency length: {0}")]
    ConvertReverseDependenciesLenght(std::num::TryFromIntError),
}

// TODO: Add metric for total amount of packages installed
#[derive(Debug)]
pub struct MetricExporter {
    rng: ThreadRng,
    last_fetch: Option<std::time::Instant>,

    metrics: Metrics,
}

#[derive(Debug)]
pub struct Metrics {
    vulnerable_packages_total: IntGauge,
    problems_found: IntGauge,
    vulnerable_packages: IntGaugeVec,
    vulnerable_reverse_packages: IntGaugeVec,
    dependent_packages: IntGaugeVec,
}

impl MetricExporter {
    pub fn new() -> Self {
        let vulnerable_packages_total = register_int_gauge!(
            "pkg_audit_exporter_vulnerable_packages_total",
            "how many packages are installed"
        )
        .expect("can not register vulnerable_packages_total");

        let problems_found = register_int_gauge!(
            "pkg_audit_exporter_problems_found",
            "how many problems where found"
        )
        .expect("can not register problems_found");

        let vulnerable_packages = register_int_gauge_vec!(
            "pkg_audit_exporter_vulnerable_packages",
            "which packages are vunerable",
            &["name", "version"]
        )
        .expect("can not register vulnerable_packages");

        let vulnerable_reverse_packages = register_int_gauge_vec!(
            "pkg_audit_exporter_vulnerable_reverse_packages",
            "which packages are depending on vunerable packages",
            &["name"]
        )
        .expect("can not register vulnerable_packages");

        let dependent_packages = register_int_gauge_vec!(
            "pkg_audit_exporter_dependent_packages",
            "how many packages are depending on this vunerable package",
            &["name"]
        )
        .expect("can not register vulnerable_packages");

        let metrics = Metrics {
            vulnerable_packages_total,
            problems_found,
            vulnerable_packages,
            vulnerable_reverse_packages,
            dependent_packages,
        };

        Self {
            rng: rand::thread_rng(),
            last_fetch: None,
            metrics,
        }
    }

    pub fn update(&mut self) -> Result<(), Error> {
        let fetch = if let Some(last_fetch) = self.last_fetch {
            let jitter = Duration::new(self.rng.gen_range(0..100), 0);
            let minutes_30 = Duration::new(30 * 60, 0);
            let max_since = jitter + minutes_30;

            max_since < Instant::now().duration_since(last_fetch)
        } else {
            true
        };

        let output = if fetch {
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
            serde_json::from_slice(&output).map_err(Error::DeserializePkgAudit)?;

        self.metrics.update(pkg_audit)?;

        Ok(())
    }
}

impl Metrics {
    fn update(&self, pkg_audit: PkgAudit) -> Result<(), Error> {
        self.vulnerable_packages_total.set(pkg_audit.pkg_count);
        let packages = pkg_audit.packages.unwrap_or_default();

        let problems_found = packages
            .values()
            .map(|package| package.issue_count + package.reverse_dependencies.len() as i64)
            .sum();

        self.problems_found.set(problems_found);

        self.vulnerable_packages.reset();
        self.dependent_packages.reset();
        self.vulnerable_reverse_packages.reset();

        for (name, package) in packages {
            self.vulnerable_packages
                .with_label_values(&[&name, &package.version])
                .set(package.issue_count);

            self.dependent_packages.with_label_values(&[&name]).set(
                package
                    .reverse_dependencies
                    .len()
                    .try_into()
                    .map_err(Error::ConvertReverseDependenciesLenght)?,
            );

            for package in package.reverse_dependencies {
                self.vulnerable_reverse_packages
                    .with_label_values(&[&package])
                    .inc();
            }
        }

        Ok(())
    }
}
