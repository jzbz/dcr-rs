// SPDX-License-Identifier: ISC
//! DCR amount helpers. Decred amounts are integer *atoms*; 1 DCR = 10⁸ atoms.

use alloc::format;
use alloc::string::String;

/// Atoms per DCR.
pub const ATOMS_PER_DCR: i64 = 100_000_000;

/// Format an atom amount for display: `"1.2345 DCR"`, trailing zeros trimmed.
pub fn format_amount(atoms: i64) -> String {
    let sign = if atoms < 0 { "-" } else { "" };
    let abs = atoms.unsigned_abs();
    let whole = abs / ATOMS_PER_DCR as u64;
    let frac = abs % ATOMS_PER_DCR as u64;
    if frac == 0 {
        return format!("{}{} DCR", sign, whole);
    }
    let mut frac_str = format!("{:08}", frac);
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{}{}.{} DCR", sign, whole, frac_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_formatting() {
        assert_eq!(format_amount(0), "0 DCR");
        assert_eq!(format_amount(100_000_000), "1 DCR");
        assert_eq!(format_amount(123_456_789), "1.23456789 DCR");
        assert_eq!(format_amount(120_000_000), "1.2 DCR");
        assert_eq!(format_amount(-50_000_000), "-0.5 DCR");
        assert_eq!(format_amount(1), "0.00000001 DCR");
        assert_eq!(format_amount(i64::MIN), "-92233720368.54775808 DCR");
    }
}
