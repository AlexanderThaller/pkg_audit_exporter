use color_eyre::eyre::{
    Context,
    Result,
};
use itertools::Itertools;
use metrics_derive::Metrics;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        family::Family,
        gauge::Gauge,
    },
    registry::Registry,
};
use tokio::process::Command;

use crate::pkg_audit::Fetcher;

// TODO: Add metric for total amount of packages installed
#[derive(Debug)]
pub(crate) struct MetricExporter {
    fetcher: Fetcher,
    pub(crate) metrics: Metrics,
    pub(crate) registry: Registry,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct InfoLabels {
    pub(crate) version: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct PackageLabels {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) urls: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ReversePackageLabels {
    pub(crate) name: String,
}

#[derive(Debug, Metrics)]
#[metrics(namespace = "pkg_audit_exporter")]
pub struct Metrics {
    #[metrics(
        name = "info",
        help = "pkg_audit_exporter information",
        init = InfoLabels {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
        set = 1
    )]
    #[expect(
        dead_code,
        reason = "this is set at the start and deserialized to prometheus metrics and never \
                  directly read"
    )]
    info: Family<InfoLabels, Gauge>,

    #[metrics(help = "How many packages are installed")]
    packages_installed: Gauge,

    #[metrics(help = "How many packages are vulnerable in total")]
    vulnerable_packages_total: Gauge,

    #[metrics(help = "How many problems were found")]
    problems_found: Gauge,

    #[metrics(help = "Vulnerable packages")]
    vulnerable_packages: Family<PackageLabels, Gauge>,

    #[metrics(help = "Vulnerable reverse packages")]
    vulnerable_reverse_packages: Family<ReversePackageLabels, Gauge>,

    #[metrics(help = "Vulnerable dependent packages")]
    dependent_packages: Family<ReversePackageLabels, Gauge>,
}

impl Default for MetricExporter {
    fn default() -> Self {
        let mut registry = Registry::default();
        let fetcher = Fetcher::default();
        let metrics = Metrics::register(&mut registry);

        Self {
            fetcher,
            metrics,
            registry,
        }
    }
}

impl MetricExporter {
    pub(crate) async fn update(&mut self) -> Result<()> {
        let packages_installed = {
            let output = Command::new("pkg")
                .arg("info")
                .output()
                .await
                .context("failed to execute pkg info")?
                .stdout;

            String::from_utf8_lossy(&output)
                .lines()
                .count()
                .try_into()
                .context("can not convert lines count for packages ")?
        };

        self.metrics.packages_installed.set(packages_installed);

        let pkg_audit = self
            .fetcher
            .fetch()
            .await
            .context("failed to fetch pkg audit")?;

        self.metrics
            .vulnerable_packages_total
            .set(pkg_audit.pkg_count);

        self.metrics.vulnerable_packages.clear();
        self.metrics.dependent_packages.clear();
        self.metrics.vulnerable_reverse_packages.clear();

        if let Some(packages) = pkg_audit.packages {
            let problems_found = packages
                .values()
                .map(|package| package.issue_count + package.reverse_dependencies.len())
                .sum::<usize>()
                .try_into()
                .context("can not convert problems found to i64")?;

            self.metrics.problems_found.set(problems_found);

            for (name, package) in packages {
                let labels = PackageLabels {
                    name: name.clone(),
                    version: package.version,
                    urls: package
                        .issues
                        .iter()
                        .map(|issue| issue.url.trim().to_string())
                        .join(","),
                };

                self.metrics.vulnerable_packages.get_or_create(&labels).set(
                    package
                        .issue_count
                        .try_into()
                        .context("can not convert issue count to i64")?,
                );

                self.metrics
                    .dependent_packages
                    .get_or_create(&ReversePackageLabels { name })
                    .set(
                        package
                            .reverse_dependencies
                            .len()
                            .try_into()
                            .context("can not convert reverse dependencies to i64")?,
                    );

                for package in package.reverse_dependencies {
                    self.metrics
                        .vulnerable_reverse_packages
                        .get_or_create(&{ ReversePackageLabels { name: package } })
                        .inc();
                }
            }
        }

        Ok(())
    }
}
