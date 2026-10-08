use super::Table;
use serde::Serialize;
/// Positional comparison of a structurally recognized table.
/// Record order remains significant; string values are not assumed to be keys.
#[derive(Clone, Debug, Serialize)]
pub struct TableComparison {
    /// Validated format shared by both tables.
    pub format: String,
    /// Number of records in source A.
    pub left_records: usize,
    /// Number of records in source B.
    pub right_records: usize,
    /// Records with exactly equal bytes at the same ordinal.
    pub unchanged_records: usize,
    /// Changed, added or removed records in source order.
    pub changes: Vec<RecordChange>,
}
/// A changed table record. Missing values denote additions/removals.
#[derive(Clone, Debug, Serialize)]
pub struct RecordChange {
    /// Original table ordinal.
    pub index: usize,
    /// Original value, absent for an addition.
    pub left: Option<String>,
    /// New value, absent for a removal.
    pub right: Option<String>,
}

pub(super) fn compare(left: &[Table], right: &[Table]) -> Vec<TableComparison> {
    left.iter()
        .zip(right)
        .filter_map(|(a, b)| {
            if a.format != b.format || a.record_width != b.record_width {
                return None;
            }
            let mut result = TableComparison {
                format: a.format.clone(),
                left_records: a.records.len(),
                right_records: b.records.len(),
                unchanged_records: 0,
                changes: Vec::new(),
            };
            for index in 0..a.records.len().max(b.records.len()) {
                let av = a.records.get(index).map(String::as_str);
                let bv = b.records.get(index).map(String::as_str);
                if av == bv {
                    result.unchanged_records += 1;
                } else {
                    result.changes.push(RecordChange {
                        index,
                        left: av.map(str::to_owned),
                        right: bv.map(str::to_owned),
                    });
                }
            }
            Some(result)
        })
        .collect()
}
