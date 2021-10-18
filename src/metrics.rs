use std::process::Command;

use prometheus_exporter::prometheus::{
    register_int_gauge_vec,
    IntGaugeVec,
};
use thiserror::Error;

use crate::parser::Parser;

#[derive(Debug, Error)]
pub enum Error {}

#[derive(Debug)]
pub struct Metrics {
    vulnerable_packages: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> Self {
        let vulnerable_packages = register_int_gauge_vec!(
            "pkg_audit_exporter_vulnerable_packages",
            "which packages are vunerable",
            &["name", "version"]
        )
        .expect("can not register vulnerable_packages");

        Self {
            vulnerable_packages,
        }
    }

    pub fn update(&self) -> Result<(), Error> {
        let output = Command::new("pkg")
            .arg("audit")
            .arg("-F")
            .output()
            .expect("failed to execute pkg audit")
            .stdout;

        let audits = Parser::parse(&output).unwrap();

        self.vulnerable_packages.reset();

        for audit in audits {
            self.vulnerable_packages
                .with_label_values(&[&audit.package.name, &audit.package.version])
                .set(1);
        }

        Ok(())
    }
}
