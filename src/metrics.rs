use std::{
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

use crate::parser::Parser;

#[derive(Debug, Error)]
pub enum Error {}

// TODO: Add metric for total amount of packages installed
#[derive(Debug)]
pub struct Metrics {
    rng: ThreadRng,
    last_fetch: Option<std::time::Instant>,

    vulnerable_packages_total: IntGauge,
    problems_found: IntGauge,
    vulnerable_packages: IntGaugeVec,
}

impl Metrics {
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

        Self {
            rng: rand::thread_rng(),
            last_fetch: None,

            vulnerable_packages_total,
            problems_found,
            vulnerable_packages,
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
                .output()
                .expect("failed to execute pkg audit")
                .stdout
        } else {
            Command::new("pkg")
                .arg("audit")
                .output()
                .expect("failed to execute pkg audit")
                .stdout
        };

        let audit = Parser::parse(&output).unwrap();

        self.vulnerable_packages_total.set(audit.installed_packages);
        self.problems_found.set(audit.problems_found);

        self.vulnerable_packages.reset();
        for package in audit.vulnerable_packages {
            // TODO: Instead of setting 1 the exporter should count
            // the amount of vunerabilities found and set that
            self.vulnerable_packages
                .with_label_values(&[&package.name, &package.version])
                .set(1);
        }

        Ok(())
    }
}
