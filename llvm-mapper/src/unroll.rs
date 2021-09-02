//! Routines and structures for "unrolling" a [`Bitstream`](llvm_bitstream::Bitstream)
//! into a block-and-record hierarchy.

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

use llvm_bitstream::parser::StreamEntry;
use llvm_bitstream::record::{Block, Record};
use llvm_bitstream::Bitstream;
use llvm_constants::IrBlockId;

use crate::block::{BlockId, Identification, Module, Strtab, Symtab};
use crate::error::Error;
use crate::map::{MapCtx, Mappable};

/// An "unrolled" record. This is internally indistinguishable from a raw bitstream
/// [`Record`](llvm_bitstream::record::Record), but is newtyped to enforce proper
/// isolation of concerns.
#[derive(Clone, Debug)]
pub struct UnrolledRecord(Record);

impl AsRef<Record> for UnrolledRecord {
    fn as_ref(&self) -> &Record {
        &self.0
    }
}

impl UnrolledRecord {
    /// Attempt to pull a UTF-8 string from this record's fields.
    ///
    /// Strings are always the last fields in a record, so only the start
    /// index is required.
    pub fn try_string(&self, idx: usize) -> Result<String, Error> {
        // If our start index lies beyond the record fields or would produce
        // an empty string, it's invalid.
        if idx >= self.0.fields.len() - 1 {
            return Err(Error::BadField(format!(
                "impossible string index: {} exceeds record fields",
                idx
            )));
        }

        // Each individual field in our string must fit into a byte.
        let raw = self.0.fields[idx..]
            .iter()
            .map(|f| u8::try_from(*f))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::BadField("impossible character value in string".into()))?;

        // Finally, the buffer itself must decode correctly.
        String::from_utf8(raw).map_err(|_| Error::BadField("invalid string encoding".into()))
    }

    /// Attempt to pull a blob of bytes from this record's fields.
    ///
    /// Blobs are always the last fields in a record, so only the start index is required.
    pub fn try_blob(&self, idx: usize) -> Result<Vec<u8>, Error> {
        // If our start index lies beyond the record fields or would produce
        // an empty string, it's invalid.
        if idx >= self.0.fields.len() - 1 {
            return Err(Error::BadField(format!(
                "impossible blob index: {} exceeds record fields",
                idx
            )));
        }

        // Each individual field in our blob must fit into a byte.
        self.0.fields[idx..]
            .iter()
            .map(|f| u8::try_from(*f))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::BadField("impossible byte value in blob".into()))
    }
}

/// A fully unrolled block within the bitstream, with potential records
/// and sub-blocks.
#[derive(Clone, Debug)]
pub struct UnrolledBlock {
    /// This block's ID.
    pub id: BlockId,
    /// The [`UnrolledRecord`](UnrolledRecord)s directly contained by this block,
    /// mapped by their codes. Blocks can have multiple records of the same code, hence
    /// the multiple values.
    // TODO(ww): Evaluate HashMap's performance. We might be better off with a specialized int map.
    records: HashMap<u64, Vec<UnrolledRecord>>,
    /// The blocks directly contained by this block, mapped by their IDs. Like with records,
    /// a block can contain multiple sub-blocks of the same ID.
    blocks: HashMap<BlockId, Vec<UnrolledBlock>>,
}

impl UnrolledBlock {
    pub(self) fn new(id: u64) -> Self {
        Self {
            id: id.into(),
            // TODO(ww): Figure out a default capacity here.
            records: HashMap::new(),
            blocks: HashMap::new(),
        }
    }

    /// Get zero or one records from this block by the given record code.
    ///
    /// Returns an error if the block has more than one record for this code.
    pub fn one_record_or_none(&self, code: u64) -> Result<Option<&UnrolledRecord>, Error> {
        match self.records.get(&code) {
            Some(recs) => match recs.len() {
                // NOTE(ww): The empty case here indicates API misuse, but we handle it out of caution.
                0 => Ok(None),
                1 => Ok(Some(&recs[0])),
                _ => Err(Error::BlockRecordMismatch(code, self.id)),
            },
            None => Ok(None),
        }
    }

    /// Get a single record from this block by its record code.
    ///
    /// Returns an error if the block either lacks an appropriate record or has more than one.
    pub fn one_record(&self, code: u64) -> Result<&UnrolledRecord, Error> {
        let records_for_code = self
            .records
            .get(&code)
            .ok_or(Error::BlockRecordMismatch(code, self.id))?;

        // The empty case here would indicate API misuse, since we should only
        // create the vector upon inserting at least one record for a given code.
        // But it doesn't hurt (much) to be cautious.
        if records_for_code.is_empty() || records_for_code.len() > 1 {
            return Err(Error::BlockRecordMismatch(code, self.id));
        }

        // Panic safety: we check for exactly one member directly above.
        Ok(&records_for_code[0])
    }

    /// Return an iterator for all records that share the given code.
    ///
    /// The returned iterator is empty if the block doesn't have any matching records.
    pub fn records(&self, code: u64) -> impl Iterator<Item = &UnrolledRecord> + '_ {
        self.records.get(&code).into_iter().flatten()
    }

    /// Get a single sub-block from this block by its block ID.
    ///
    /// Returns an error if the block either lacks an appropriate block or has more than one.
    pub fn one_block(&self, id: BlockId) -> Result<&UnrolledBlock, Error> {
        let blocks_for_id = self
            .blocks
            .get(&id)
            .ok_or(Error::BlockBlockMismatch(id, self.id))?;

        // The empty case here would indicate API misuse, since we should only
        // create the vector upon inserting at least one block for a given ID.
        // But it doesn't hurt (much) to be cautious.
        if blocks_for_id.is_empty() || blocks_for_id.len() > 1 {
            return Err(Error::BlockBlockMismatch(id, self.id));
        }

        // Panic safety: we check for exactly one member directly above.
        Ok(&blocks_for_id[0])
    }
}

/// A fully unrolled bitcode structure, taken from a bitstream.
///
/// Every `UnrolledBitcode` has a list of `BitstreamModule`s that it contains, each of
/// which corresponds to a single LLVM IR module. In the simplest case, there will only be one.
#[derive(Debug)]
pub struct UnrolledBitcode {
    pub(crate) modules: Vec<BitcodeModule>,
}

impl TryFrom<&[u8]> for UnrolledBitcode {
    type Error = Error;

    fn try_from(buf: &[u8]) -> Result<UnrolledBitcode, Self::Error> {
        let (_, bitstream) = Bitstream::from(buf)?;

        bitstream.try_into()
    }
}

impl<T: AsRef<[u8]>> TryFrom<Bitstream<T>> for UnrolledBitcode {
    type Error = Error;

    fn try_from(mut bitstream: Bitstream<T>) -> Result<UnrolledBitcode, Self::Error> {
        fn enter_block<T: AsRef<[u8]>>(
            bitstream: &mut Bitstream<T>,
            block: Block,
        ) -> Result<UnrolledBlock, Error> {
            let mut unrolled_block = UnrolledBlock::new(block.block_id);

            // Once we're in a block, we do the following:
            // 1. Take records, and add them to the current unrolled block;
            // 2. Take sub-blocks, and enter them, adding them to our sub-block map;
            // 3. Visit the end of our own block and return so that the caller
            //    (which is either the bitstream context or another parent block)
            //    can add us to its block map.
            loop {
                let entry = bitstream.next().ok_or_else(|| {
                    Error::BadUnroll("unexpected stream end during unroll".into())
                })?;

                match entry? {
                    StreamEntry::Record(record) => unrolled_block
                        .records
                        .entry(record.code)
                        .or_insert_with(Vec::new)
                        .push(UnrolledRecord(record)),
                    StreamEntry::SubBlock(block) => {
                        let unrolled_child = enter_block(bitstream, block)?;
                        unrolled_block
                            .blocks
                            .entry(unrolled_child.id)
                            .or_insert_with(Vec::new)
                            .push(unrolled_child);
                    }
                    StreamEntry::EndBlock => {
                        // End our current block scope.
                        break;
                    }
                }
            }

            Ok(unrolled_block)
        }

        let mut partial_modules = Vec::new();

        // Unrolling a bitstream into an `UnrolledBitcode` is a little involved:
        //
        // 1. There are multiple top-level blocks, each of which needs to be consumed.
        // 2. Certain top-level blocks need to be grouped together to form a single BitcodeModule.
        // 3. There can be multiple BitcodeModules-worth of top-level blocks in the stream.
        loop {
            // `None` means that we've exhausted the bitstream; we're done.
            let entry = bitstream.next();
            if entry.is_none() {
                break;
            }

            // Take a top-level block from the stream.
            let top_block = {
                // Unwrap safety: we explicitly check the `None` case above.
                // NOTE(ww): Other parts of the parser should be defensive against a malformed
                // bitstream here, but it's difficult to represent that at the type level during unrolling.
                #[allow(clippy::unwrap_used)]
                let block = entry.unwrap()?.as_block().ok_or_else(|| {
                    Error::BadUnroll("bitstream has non-blocks at the top-level scope".into())
                })?;

                enter_block(&mut bitstream, block)?
            };

            // Our top-level block can be one of four cases, if it's valid.
            //
            // Handle each accordingly.
            match top_block.id {
                BlockId::Ir(IrBlockId::Identification) => {
                    // We've unrolled an IDENTIFICATION_BLOCK; this indicates the start of a new
                    // bitcode module. Create a fresh PartialBitcodeModule to fill in, as more
                    // top-level blocks become available.
                    partial_modules.push(PartialBitcodeModule::new(top_block));
                }
                BlockId::Ir(IrBlockId::Module) => {
                    // We've unrolled a MODULE_BLOCK; this contains the vast majority of the
                    // state associated with an LLVM IR module. Grab the most recent
                    // PartialBitcodeModule and fill it in, erroring appropriately if it already
                    // has a module.
                    //
                    // NOTE(ww): We could encounter a top-level sequence that looks like this:
                    //   [IDENTIFICATION_BLOCK, IDENTIFICATION_BLOCK, MODULE_BLOCK]
                    // This would be malformed and in principle we should catch it here by searching
                    // for the first PartialBitcodeModule lacking a module instead of taking
                    // the most recent one, but the PartialBitcodeModule -> BitcodeModule reification
                    // step will take care of that for us.
                    let last_partial = partial_modules.last_mut().ok_or_else(|| {
                        Error::BadUnroll("malformed bitstream: MODULE_BLOCK with no preceding IDENTIFICATION_BLOCK".into())
                    })?;

                    match &last_partial.module {
                        Some(_) => {
                            return Err(Error::BadUnroll(
                                "malformed bitstream: adjacent MODULE_BLOCKs".into(),
                            ))
                        }
                        None => last_partial.module = Some(top_block),
                    }
                }
                BlockId::Ir(IrBlockId::Strtab) => {
                    // We've unrolled a STRTAB_BLOCK; this contains the string table for one or
                    // more preceding modules. Any modules that don't already have their own string
                    // table are given their own copy of this one.
                    //
                    // NOTE(ww): Again, we could encounter a sequence that looks like this:
                    //   [..., STRTAB_BLOCK, STRTAB_BLOCK]
                    // This actually wouldn't be malformed, but is *is* nonsense: the second
                    // STRTAB_BLOCK would have no effect on any BitcodeModule, since the first one
                    // in sequence would already have been used for every prior module.
                    // We don't bother catching this at the moment since LLVM's own reader doesn't
                    // and it isn't erroneous per se (just pointless).
                    for prev_partial in partial_modules
                        .iter_mut()
                        .rev()
                        .take_while(|p| p.strtab.is_none())
                    {
                        prev_partial.strtab = Some(top_block.clone());
                    }
                }
                BlockId::Ir(IrBlockId::Symtab) => {
                    // We've unrolled a SYMTAB_BLOCK; this contains the symbol table (which, in
                    // turn, references the string table) for one or more preceding modules. Any
                    // modules that don't already have their own symbol table are given their own
                    // copy of this one.
                    //
                    // NOTE(ww): The same nonsense layout with STRTAB_BLOCK applies here.
                    for prev_partial in partial_modules
                        .iter_mut()
                        .rev()
                        .take_while(|p| p.symtab.is_none())
                    {
                        prev_partial.symtab = Some(top_block.clone());
                    }
                }
                _ => {
                    return Err(Error::BadUnroll(format!(
                        "unexpected top-level block: {:?}",
                        top_block.id
                    )))
                }
            }
        }

        let modules = partial_modules
            .into_iter()
            .map(|p| p.reify())
            .collect::<Result<Vec<_>, _>>()?;
        let unrolled = UnrolledBitcode { modules };

        Ok(unrolled)
    }
}

/// An internal, partial representation of a bitcode module, used when parsing each bitcode module
/// to avoid polluting the `BitcodeModule` structure with optional types.
#[derive(Debug)]
struct PartialBitcodeModule {
    identification: UnrolledBlock,
    module: Option<UnrolledBlock>,
    strtab: Option<UnrolledBlock>,
    symtab: Option<UnrolledBlock>,
}

impl PartialBitcodeModule {
    /// Create a new `PartialBitcodeModule`.
    pub(self) fn new(identification: UnrolledBlock) -> Self {
        Self {
            identification: identification,
            module: None,
            strtab: None,
            symtab: None,
        }
    }

    /// Reify this `PartialBitcodeModule into a concrete `BitcodeModule`, mapping
    /// each block along the way.
    ///
    /// Returns an error if the `PartialBitcodeModule` is lacking necessary state, or if
    /// block and record mapping fails for any reason.
    pub(self) fn reify(self) -> Result<BitcodeModule, Error> {
        let mut ctx = MapCtx::default();

        // Grab the string table early, so that we can move it into our mapping context and
        // use it for the remainder of the mapping phase.
        let strtab = Strtab::try_map(
            self.strtab.ok_or_else(|| {
                Error::BadUnroll("missing STRTAB_BLOCK for bitcode module".into())
            })?,
            &mut ctx,
        )?;

        ctx.strtab = Some(strtab);

        let identification = Identification::try_map(self.identification, &mut ctx)?;
        let module = Module::try_map(
            self.module.ok_or_else(|| {
                Error::BadUnroll("missing MODULE_BLOCK for bitcode module".into())
            })?,
            &mut ctx,
        )?;
        let symtab = self
            .symtab
            .map(|s| Symtab::try_map(s, &mut ctx))
            .transpose()?;

        #[allow(clippy::unwrap_used)]
        Ok(BitcodeModule {
            identification: identification,
            module: module,
            // Unwrap safety: we unconditionally assign `strtab` to `Some(...)` above.
            strtab: ctx.strtab.unwrap(),
            symtab: symtab,
        })
    }
}

/// A `BitcodeModule` encapsulates the top-level pieces of bitstream state needed for
/// a single LLVM bitcode module: the `IDENTIFICATION_BLOCK`, the `MODULE_BLOCK` itself,
/// a `STRTAB_BLOCK`, and a `SYMTAB_BLOCK` (if the last is present). A bitstream can
/// contain multiple LLVM modules (e.g. if produced by `llvm-cat -b`), so parsing a bitstream
/// can result in multiple `BitcodeModule`s.
#[derive(Debug)]
pub struct BitcodeModule {
    /// The identification block associated with this module.
    pub identification: Identification,

    /// The module block associated with this module.
    pub module: Module,

    /// The string table associated with this module.
    pub strtab: Strtab,

    /// The symbol table associated with this module, if it has one.
    pub symtab: Option<Symtab>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrolled_record_try_string() {
        let record = UnrolledRecord(Record {
            abbrev_id: None,
            code: 0,
            fields: b"\xff\xffvalid string!".iter().map(|b| *b as u64).collect(),
        });

        assert_eq!(record.try_string(2).unwrap(), "valid string!");
        assert_eq!(record.try_string(8).unwrap(), "string!");

        assert!(record.try_string(0).is_err());
        assert!(record.try_string(record.0.fields.len()).is_err());
        assert!(record.try_string(record.0.fields.len() - 1).is_err());
    }

    #[test]
    fn test_unrolled_record_try_blob() {
        let record = UnrolledRecord(Record {
            abbrev_id: None,
            code: 0,
            fields: b"\xff\xffvalid string!".iter().map(|b| *b as u64).collect(),
        });

        assert_eq!(record.try_blob(0).unwrap(), b"\xff\xffvalid string!");
        assert_eq!(record.try_blob(8).unwrap(), b"string!");

        assert!(record.try_blob(record.0.fields.len()).is_err());
        assert!(record.try_blob(record.0.fields.len() - 1).is_err());
    }
}