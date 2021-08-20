use std::{
    io,
    io::BufRead,
};

use crate::audit::Audit;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can not extract line: {0}")]
    LineError(io::Error),
}

pub struct Parser {}

impl Parser {
    pub fn parse(input: &[u8]) -> Result<Vec<Audit>, Error> {
        input.lines().filter_map(Self::parse_line).collect()
    }

    fn parse_line(line: io::Result<String>) -> Option<Result<Audit, Error>> {
        line.map_err(Error::LineError)
            .and_then(|line| {
                let split = line.split_ascii_whitespace().collect::<Vec<_>>();

                match split.as_slice() {
                    [package, "is", "vulnerable:"] => Ok(Some(Audit {
                        package: package.to_string(),
                    })),

                    _ => Ok(None),
                }
            })
            .transpose()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn parse_pkg_audit_output() {
        let input = include_bytes!("../resources/pkg_audit_output");

        let audits = super::Parser::parse(input).unwrap();

        assert_eq!(audits.len(), 5);
    }
}
