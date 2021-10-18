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
}

pub struct Parser {}

impl Parser {
    pub fn parse(input: &[u8]) -> Result<Vec<Audit>, Error> {
        input.lines().filter_map(Self::parse_line).collect()
    }

    fn parse_line(line: io::Result<String>) -> Option<Result<Audit, Error>> {
        line.map_err(Error::Line)
            .and_then(|line| {
                let split = line.split_ascii_whitespace().collect::<Vec<_>>();

                match split.as_slice() {
                    [package, "is", "vulnerable:"] => {
                        let package = package.parse().map_err(Error::Package)?;

                        Ok(Some(Audit { package }))
                    }

                    _ => Ok(None),
                }
            })
            .transpose()
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

        let expected = vec![
            Audit {
                package: Package {
                    name: "curl".into(),
                    version: "7.77.0".into(),
                },
            },
            Audit {
                package: Package {
                    name: "postgresql13-server".into(),
                    version: "13.3_1".into(),
                },
            },
            Audit {
                package: Package {
                    name: "go".into(),
                    version: "1.16.5,1".into(),
                },
            },
            Audit {
                package: Package {
                    name: "redis".into(),
                    version: "6.0.14".into(),
                },
            },
            Audit {
                package: Package {
                    name: "ruby".into(),
                    version: "2.7.3_2,1".into(),
                },
            },
        ];

        let got = super::Parser::parse(input).unwrap();

        assert_eq!(expected, got);
    }
}
