//! Shared comparison facts. Comparison is not permission to program a device.
use serde::Serialize;

/// A versioned hardware fingerprint, independent of display model names.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HardwareFamily {
    /// Fingerprint namespace and version.
    pub scheme: String,
    /// Opaque fingerprint.
    pub id: String,
}
/// Relationship between fingerprints produced under known schemes.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum FamilyRelationship {
    /// Both fingerprints match under one scheme.
    Same,
    /// Both fingerprints differ under one scheme.
    Different,
    /// At least one fingerprint or scheme is missing.
    Unknown,
    /// The schemes differ; fingerprints must be recomputed before comparison.
    NotComparable,
}
impl FamilyRelationship {
    /// Compare namespace and value; two missing values are never equal evidence.
    pub fn compare(left: Option<(&str, &str)>, right: Option<(&str, &str)>) -> Self {
        match (left, right) {
            (Some((a, x)), Some((b, y)))
                if !a.is_empty() && !b.is_empty() && !x.is_empty() && !y.is_empty() =>
            {
                if a != b {
                    Self::NotComparable
                } else if x == y {
                    Self::Same
                } else {
                    Self::Different
                }
            }
            _ => Self::Unknown,
        }
    }
    /// Compare complete family records.
    pub fn between(left: Option<&HardwareFamily>, right: Option<&HardwareFamily>) -> Self {
        Self::compare(
            left.map(|f| (f.scheme.as_str(), f.id.as_str())),
            right.map(|f| (f.scheme.as_str(), f.id.as_str())),
        )
    }
}
/// Exact decoded content relationship, separate from normalized similarity.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Contents {
    /// Complete decoded content digests match.
    Identical,
    /// Complete decoded content digests differ.
    Different,
    /// Missing content or coverage prevents a complete comparison.
    Incomplete,
}
/// Advertised naming relationship; it never gates readback success.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Naming {
    /// Both names are known and equal.
    Same,
    /// Known names differ.
    Different,
    /// At least one name is unavailable.
    Unknown,
}
/// Direction is from the left source to the right target.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum VersionRelationship {
    /// The labels match within a known common release series.
    Same,
    /// Target revision is numerically newer within that series.
    Newer,
    /// Target revision is numerically older within that series.
    Older,
    /// Both revisions exist but their ordering is not established.
    NotComparable,
    /// At least one revision is missing.
    Unknown,
}
impl VersionRelationship {
    /// Only compare dotted numeric revisions in an explicitly common lineage.
    /// Suffixes and OEM labels are never stripped or lexicographically ordered.
    pub fn compare(left: &str, right: &str, same_lineage: bool) -> Self {
        if left.is_empty() || right.is_empty() {
            return Self::Unknown;
        }
        if !same_lineage {
            return Self::NotComparable;
        }
        if left == right {
            return Self::Same;
        }
        fn numeric(s: &str) -> Option<Vec<u64>> {
            if !s.contains('.') {
                return None;
            }
            s.split('.')
                .map(|p| {
                    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                        None
                    } else {
                        p.parse().ok()
                    }
                })
                .collect()
        }
        match (numeric(left), numeric(right)) {
            (Some(mut a), Some(mut b)) => {
                let n = a.len().max(b.len());
                a.resize(n, 0);
                b.resize(n, 0);
                match b.cmp(&a) {
                    std::cmp::Ordering::Equal => Self::Same,
                    std::cmp::Ordering::Greater => Self::Newer,
                    std::cmp::Ordering::Less => Self::Older,
                }
            }
            _ => Self::NotComparable,
        }
    }
}
/// Provider facts used by lightweight and detailed comparisons alike.
#[derive(Clone, Debug, Default)]
pub struct ComponentIdentity {
    /// Package/firmware display name supplied by the provider.
    pub name: String,
    /// Advertised revision; not proof of content.
    pub revision: String,
    /// Provider-established release series including component/edition.
    pub lineage: Option<String>,
}
/// Independent facts; multiple differences may be true simultaneously.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ComparisonFacts {
    /// Exact decoded content relation.
    pub contents: Contents,
    /// Display-name relation.
    pub naming: Naming,
    /// Whether both known advertised revision strings differ, independent of ordering.
    pub revision_label_changed: Option<bool>,
    /// Target revision direction, where established.
    pub version: VersionRelationship,
    /// Versioned hardware relationship.
    pub family: FamilyRelationship,
}
impl ComponentIdentity {
    /// Compare facts without decoding again or inferring flash compatibility.
    pub fn compare(
        &self,
        other: &Self,
        contents: Contents,
        family: FamilyRelationship,
    ) -> ComparisonFacts {
        let naming = if self.name.is_empty() || other.name.is_empty() {
            Naming::Unknown
        } else if self.name == other.name {
            Naming::Same
        } else {
            Naming::Different
        };
        let same_lineage = self
            .lineage
            .as_ref()
            .zip(other.lineage.as_ref())
            .is_some_and(|(a, b)| !a.is_empty() && a == b);
        ComparisonFacts {
            contents,
            naming,
            revision_label_changed: (!self.revision.is_empty() && !other.revision.is_empty())
                .then(|| self.revision != other.revision),
            version: VersionRelationship::compare(&self.revision, &other.revision, same_lineage),
            family,
        }
    }
}

impl ComparisonFacts {
    /// English diagnostic explanation; UI adapters render the typed facts.
    /// Upgrade/downgrade describe version direction,
    /// never permission to flash or proof of behavioral equivalence.
    pub fn summary(&self) -> &'static str {
        match self.contents {
            Contents::Incomplete => "Comparison incomplete",
            Contents::Identical if self.naming == Naming::Different => {
                "Same firmware, different branding"
            }
            Contents::Identical if self.revision_label_changed == Some(true) => {
                "Same firmware, different version label"
            }
            Contents::Identical => "Same firmware",
            Contents::Different if self.family == FamilyRelationship::Different => {
                "Different firmware and hardware family"
            }
            Contents::Different => match self.version {
                VersionRelationship::Newer => "Different firmware, newer version",
                VersionRelationship::Older => "Different firmware, older version",
                VersionRelationship::Same => "Different firmware, same version",
                _ if self.family == FamilyRelationship::Same => {
                    "Different firmware, same hardware family"
                }
                _ => "Different firmware",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_and_revision_are_independent_and_summary_does_not_invent_an_upgrade() {
        let a = ComponentIdentity {
            name: "Drive".into(),
            revision: "1.00".into(),
            lineage: Some("edition".into()),
        };
        let mut b = a.clone();
        b.revision = "1.10".into();
        let same = a.compare(&b, Contents::Identical, FamilyRelationship::Same);
        assert_eq!(same.version, VersionRelationship::Newer);
        assert_eq!(same.summary(), "Same firmware, different version label");
        b.revision = a.revision.clone();
        let changed = a.compare(&b, Contents::Different, FamilyRelationship::Same);
        assert_eq!(changed.version, VersionRelationship::Same);
        assert_eq!(changed.summary(), "Different firmware, same version");
    }

    #[test]
    fn namespaces_and_missing_families_are_not_false_matches() {
        assert_eq!(
            FamilyRelationship::compare(None, None),
            FamilyRelationship::Unknown
        );
        assert_eq!(
            FamilyRelationship::compare(Some(("v1", "a")), Some(("v2", "a"))),
            FamilyRelationship::NotComparable
        );
        assert_eq!(
            FamilyRelationship::compare(Some(("v1", "a")), Some(("v1", "b"))),
            FamilyRelationship::Different
        );
        assert_eq!(
            FamilyRelationship::compare(Some(("v1", "a")), Some(("v1", "a"))),
            FamilyRelationship::Same
        );
    }
    #[test]
    fn revision_direction_needs_a_series_and_never_discards_suffixes() {
        use VersionRelationship::*;
        assert_eq!(VersionRelationship::compare("1.02", "1.10", true), Newer);
        assert_eq!(VersionRelationship::compare("1.10", "1.02", true), Older);
        assert_eq!(VersionRelationship::compare("1.0", "1.00", true), Same);
        assert_eq!(
            VersionRelationship::compare("1.10EU", "1.10US", true),
            NotComparable
        );
        assert_eq!(
            VersionRelationship::compare("HLE2", "1.14", false),
            NotComparable
        );
        assert_eq!(
            VersionRelationship::compare("1.00", "1.00", false),
            NotComparable
        );
        assert_eq!(VersionRelationship::compare("", "1.14", true), Unknown);
    }
    #[test]
    fn identical_contents_can_have_different_branding_and_unordered_versions() {
        let a = ComponentIdentity {
            name: "Slimtype EB1".into(),
            revision: "HLE2".into(),
            lineage: None,
        };
        let b = ComponentIdentity {
            name: "BDR-UD04".into(),
            revision: "1.14".into(),
            lineage: None,
        };
        let facts = a.compare(&b, Contents::Identical, FamilyRelationship::Same);
        assert_eq!(facts.contents, Contents::Identical);
        assert_eq!(facts.naming, Naming::Different);
        assert_eq!(facts.version, VersionRelationship::NotComparable);
        assert_eq!(facts.family, FamilyRelationship::Same);
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    #[test]
    fn family_needs_complete_fingerprints_under_one_scheme() {
        use FamilyRelationship::*;
        let compare = FamilyRelationship::compare;
        assert_eq!(compare(Some(("s1", "a")), Some(("s1", "a"))), Same);
        assert_eq!(compare(Some(("s1", "a")), Some(("s1", "b"))), Different);
        assert_eq!(compare(Some(("s1", "a")), Some(("s2", "a"))), NotComparable);
        for incomplete in [("", "a"), ("s1", "")] {
            assert_eq!(compare(Some(incomplete), Some(("s1", "a"))), Unknown);
            assert_eq!(compare(Some(("s1", "a")), Some(incomplete)), Unknown);
            assert_eq!(compare(Some(incomplete), Some(incomplete)), Unknown);
        }
        assert_eq!(compare(None, Some(("s1", "a"))), Unknown);
        assert_eq!(compare(Some(("s1", "a")), None), Unknown);
        assert_eq!(compare(None, None), Unknown);
        let family = |scheme: &str, id: &str| HardwareFamily {
            scheme: scheme.into(),
            id: id.into(),
        };
        assert_eq!(
            FamilyRelationship::between(Some(&family("s", "1")), Some(&family("s", "1"))),
            Same
        );
        assert_eq!(FamilyRelationship::between(None, None), Unknown);
    }

    #[test]
    fn versions_order_only_plain_dotted_numbers_in_one_lineage() {
        use VersionRelationship::*;
        let compare = VersionRelationship::compare;
        assert_eq!(compare("", "1.0", true), Unknown);
        assert_eq!(compare("1.0", "", true), Unknown);
        assert_eq!(compare("1.0", "1.1", false), NotComparable);
        assert_eq!(compare("1.0", "1.0", true), Same);
        assert_eq!(compare("1.0", "1.1", true), Newer);
        assert_eq!(compare("1.10", "1.9", true), Older);
        assert_eq!(compare("1.0", "1.0.0", true), Same);
        assert_eq!(compare("1.0", "1.0.1", true), Newer);
        assert_eq!(compare("2", "3", true), NotComparable);
        assert_eq!(compare("1.0a", "1.1", true), NotComparable);
        assert_eq!(compare("1.+2", "1.3", true), NotComparable);
        assert_eq!(compare("1..2", "1.3", true), NotComparable);
        assert_eq!(compare("1.0", "1.-1", true), NotComparable);
    }

    fn identity(name: &str, revision: &str, lineage: Option<&str>) -> ComponentIdentity {
        ComponentIdentity {
            name: name.into(),
            revision: revision.into(),
            lineage: lineage.map(str::to_owned),
        }
    }

    #[test]
    fn identity_facts_are_independent() {
        let same = FamilyRelationship::Same;
        let facts =
            |a: ComponentIdentity, b: ComponentIdentity| a.compare(&b, Contents::Different, same);
        let base = identity("Drive", "1.0", Some("edition"));
        let f = facts(base.clone(), identity("Drive", "1.1", Some("edition")));
        assert_eq!(f.naming, Naming::Same);
        assert_eq!(f.revision_label_changed, Some(true));
        assert_eq!(f.version, VersionRelationship::Newer);
        assert_eq!(
            facts(base.clone(), identity("Other", "1.0", Some("edition"))).naming,
            Naming::Different
        );
        assert_eq!(
            facts(base.clone(), identity("", "1.0", Some("edition"))).naming,
            Naming::Unknown
        );
        assert_eq!(
            facts(identity("", "1.0", None), base.clone()).naming,
            Naming::Unknown
        );
        assert_eq!(
            facts(base.clone(), identity("Drive", "1.0", Some("edition"))).revision_label_changed,
            Some(false)
        );
        assert_eq!(
            facts(base.clone(), identity("Drive", "", Some("edition"))).revision_label_changed,
            None
        );
        assert_eq!(
            facts(identity("Drive", "", None), base.clone()).revision_label_changed,
            None
        );
        for other in [None, Some(""), Some("series")] {
            let different = facts(base.clone(), identity("Drive", "1.1", other));
            assert_eq!(
                different.version,
                VersionRelationship::NotComparable,
                "{other:?}"
            );
        }
        let empty = facts(
            identity("D", "1.0", Some("")),
            identity("D", "1.1", Some("")),
        );
        assert_eq!(empty.version, VersionRelationship::NotComparable);
        let one_sided = facts(
            identity("D", "1.0", Some("edition")),
            identity("D", "1.1", None),
        );
        assert_eq!(one_sided.version, VersionRelationship::NotComparable);
    }

    #[test]
    fn summaries_follow_the_fixed_precedence() {
        use {Contents::*, FamilyRelationship as F, Naming as N, VersionRelationship as V};
        let facts = |contents, naming, label, version, family| ComparisonFacts {
            contents,
            naming,
            revision_label_changed: label,
            version,
            family,
        };
        let s = |f: ComparisonFacts| f.summary();
        assert_eq!(
            s(facts(
                Incomplete,
                N::Different,
                Some(true),
                V::Newer,
                F::Different
            )),
            "Comparison incomplete"
        );
        assert_eq!(
            s(facts(
                Identical,
                N::Different,
                Some(true),
                V::Newer,
                F::Different
            )),
            "Same firmware, different branding"
        );
        assert_eq!(
            s(facts(Identical, N::Same, Some(true), V::Same, F::Same)),
            "Same firmware, different version label"
        );
        assert_eq!(
            s(facts(Identical, N::Same, Some(false), V::Same, F::Same)),
            "Same firmware"
        );
        assert_eq!(
            s(facts(Identical, N::Unknown, None, V::Unknown, F::Unknown)),
            "Same firmware"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::Newer, F::Different)),
            "Different firmware and hardware family"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::Newer, F::Same)),
            "Different firmware, newer version"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::Older, F::Same)),
            "Different firmware, older version"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::Same, F::Same)),
            "Different firmware, same version"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::NotComparable, F::Same)),
            "Different firmware, same hardware family"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::Unknown, F::Same)),
            "Different firmware, same hardware family"
        );
        assert_eq!(
            s(facts(Different, N::Same, None, V::Unknown, F::Unknown)),
            "Different firmware"
        );
        assert_eq!(
            s(facts(
                Different,
                N::Same,
                None,
                V::NotComparable,
                F::NotComparable
            )),
            "Different firmware"
        );
    }
}
