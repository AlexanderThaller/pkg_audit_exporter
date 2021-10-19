use serde::{
    Deserialize,
    Serialize,
};
use std::collections::HashMap as Map;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PkgAudit {
    pub pkg_count: i64,
    pub packages: Option<Map<String, Package>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub version: String,
    pub issue_count: i64,
    pub issues: Vec<Issue>,

    #[serde(rename = "reverse dependencies")]
    pub reverse_dependencies: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    #[serde(rename = "Affected versions")]
    pub affected_versions: Vec<String>,
    pub description: String,
    pub url: String,
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
