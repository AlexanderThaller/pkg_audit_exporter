use std::{
    io,
    io::BufRead,
};

use crate::audit::Audit;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can not extract line: {0}")]
    Line(io::Error),

    #[error("failed to parse package: {0}")]
    Package(crate::audit::package::Error),

    #[error("can not parse amount of problems: {0}")]
    InvalidProblems(std::num::ParseIntError),

    #[error("can not parse amount of packages: {0}")]
    InvalidPackages(std::num::ParseIntError),
}

pub struct Parser {
    audit: Audit,
}

impl Parser {
    pub fn parse(input: &[u8]) -> Result<Audit, Error> {
        let mut parser = Parser {
            audit: Audit::default(),
        };

        input.lines().try_for_each(|line| parser.parse_line(line))?;

        Ok(parser.audit)
    }

    fn parse_line(&mut self, line: io::Result<String>) -> Result<(), Error> {
        let line = line.map_err(Error::Line)?;

        let split = line.split_ascii_whitespace().collect::<Vec<_>>();

        match split.as_slice() {
            [package, "is", "vulnerable:"] => {
                let package = package.parse().map_err(Error::Package)?;
                self.audit.vulnerable_packages.push(package);
            }

            [problems_found, "problem(s)", "in", installed_packages, "installed", "package(s)", "found."] =>
            {
                self.audit.problems_found =
                    problems_found.parse().map_err(Error::InvalidProblems)?;
                self.audit.installed_packages =
                    installed_packages.parse().map_err(Error::InvalidPackages)?;
            }

            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use crate::audit::{
        package::Package,
        Audit,
    };

    #[test]
    fn parse() {
        let input = include_bytes!("../resources/pkg_audit_output");

        let got = super::Parser::parse(input).unwrap();

        let expected = Audit {
            installed_packages: 5,
            problems_found: 6,
            vulnerable_packages: vec![
                Package {
                    name: "curl".into(),
                    version: "7.77.0".into(),
                },
                Package {
                    name: "postgresql13-server".into(),
                    version: "13.3_1".into(),
                },
                Package {
                    name: "go".into(),
                    version: "1.16.5,1".into(),
                },
                Package {
                    name: "redis".into(),
                    version: "6.0.14".into(),
                },
                Package {
                    name: "ruby".into(),
                    version: "2.7.3_2,1".into(),
                },
            ],
        };

        assert_eq!(expected, got);
    }
}
