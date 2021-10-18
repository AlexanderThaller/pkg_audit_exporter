#[derive(Debug, Default, Eq, PartialEq)]
pub struct Audit {
    pub installed_packages: i64,
    pub problems_found: i64,
    pub vulnerable_packages: Vec<package::Package>,
}

pub mod package {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum Error {
        #[error("not enough dashes (-) found, expected at least two (2) got only {0}")]
        NotEnoughDashes(usize),
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct Package {
        pub name: String,
        pub version: String,
    }

    impl std::str::FromStr for Package {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let split = s.split('-').collect::<Vec<_>>();

            match split.as_slice() {
                [] | [_] => Err(Error::NotEnoughDashes(split.len())),

                [name @ .., version] => {
                    let name = name.join("-");
                    let version = version.to_string();

                    Ok(Self { name, version })
                }
            }
        }
    }

    #[cfg(test)]
    mod test {
        use pretty_assertions::assert_eq;
        use std::str::FromStr;

        #[test]
        fn parse() {
            let input = "postgresql13-server-13.3_1";

            let expected = super::Package {
                name: "postgresql13-server".into(),
                version: "13.3_1".into(),
            };

            let got = super::Package::from_str(input).unwrap();

            assert_eq!(expected, got);
        }
    }
}
