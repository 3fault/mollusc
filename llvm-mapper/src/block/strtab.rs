//! Functionality for mapping the `STRTAB_BLOCK` block.

use std::str::Utf8Error;

use llvm_constants::{IrBlockId, StrtabCode};
use llvm_support::StrtabRef;
use thiserror::Error;

use crate::block::{BlockMapError, IrBlock};
use crate::map::MapCtx;
use crate::unroll::UnrolledBlock;

/// Errors that can occur when accessing a string table.
#[derive(Debug, Error)]
pub enum StrtabError {
    /// The requested range is invalid.
    #[error("requested range in string table is invalid")]
    BadRange,
    /// The requested string is not UTF-8.
    #[error("could not decode range into a UTF-8 string: {0}")]
    BadString(#[from] Utf8Error),
}

/// Models the `STRTAB_BLOCK` block.
#[derive(Clone, Debug)]
pub struct Strtab(Vec<u8>);

impl AsRef<[u8]> for Strtab {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl IrBlock for Strtab {
    const BLOCK_ID: IrBlockId = IrBlockId::Strtab;

    fn try_map_inner(block: &UnrolledBlock, _ctx: &mut MapCtx) -> Result<Self, BlockMapError> {
        // TODO(ww): The docs also claim that there's only one STRTAB_BLOB per STRTAB_BLOCK,
        // but at least one person has reported otherwise here:
        // https://lists.llvm.org/pipermail/llvm-dev/2020-August/144327.html
        // Needs investigation.
        let strtab = {
            let strtab = block.one_record(StrtabCode::Blob as u64)?;

            strtab.try_blob(0)?
        };

        Ok(Self(strtab))
    }
}

impl Strtab {
    /// Get a string in the string table by its index and length.
    ///
    /// Returns `None` on all of the error conditions associated with
    /// [`try_get`](Strtab::try_get).
    pub fn get(&self, sref: &StrtabRef) -> Option<&str> {
        self.try_get(sref).ok()
    }

    /// Get a string in the string table by its index and length.
    ///
    /// Returns an error if the requested span is invalid, or if the extracted
    /// slice isn't a valid string.
    pub fn try_get(&self, sref: &StrtabRef) -> Result<&str, StrtabError> {
        let inner = self.as_ref();

        if sref.size == 0 || sref.offset >= inner.len() || sref.offset + sref.size > inner.len() {
            return Err(StrtabError::BadRange);
        }

        Ok(std::str::from_utf8(
            &inner[sref.offset..sref.offset + sref.size],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sref(tup: (usize, usize)) -> StrtabRef {
        tup.into()
    }

    #[test]
    fn test_strtab() {
        let inner = "this is a string table";
        let strtab = Strtab(inner.into());
        assert_eq!(strtab.get(&sref((0, 4))).unwrap(), "this");
        assert_eq!(strtab.get(&sref((0, 7))).unwrap(), "this is");
        assert_eq!(strtab.get(&sref((8, 14))).unwrap(), "a string table");
        assert_eq!(
            strtab.get(&sref((0, inner.len()))).unwrap(),
            "this is a string table"
        );

        assert!(strtab.get(&sref((inner.len(), 0))).is_none());
        assert!(strtab.get(&sref((0, inner.len() + 1))).is_none());
        assert!(strtab.get(&sref((0, 0))).is_none());
    }
}