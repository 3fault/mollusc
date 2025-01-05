//! Functionality for mapping the `PARAMATTR_BLOCK` and `PARAMATTR_GROUP_BLOCK` blocks.

use std::convert::{TryFrom, TryInto};

use hashbrown::HashMap;
use llvm_support::bitcodes::AttributeCode;
use llvm_support::{slice_to_apint, ApInt, AttributeId, AttributeKind, MaybeAlign};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;

use crate::map::{MapError, PartialMapCtx};
use crate::unroll::{Block, Record};

/// Errors that can occur when mapping attribute blocks.
#[derive(Debug, Error)]
pub enum AttributeError {
    /// An unknown record code was seen.
    #[error("unknown attribute code")]
    UnknownAttributeCode(#[from] TryFromPrimitiveError<AttributeCode>),

    /// An unknown attribute kind (format) was seen.
    #[error("unknown attribute kind")]
    UnknownAttributeKind(#[from] TryFromPrimitiveError<AttributeKind>),

    /// The given code was seen in an unexpected block.
    #[error("wrong block for code: {0:?}")]
    WrongBlock(AttributeCode),

    /// The attribute couldn't be constructed because of missing fields.
    #[error("attribute structure too short")]
    TooShort,

    /// The attribute has an invalid string key or string balue.
    #[error("bad attribute string")]
    BadString,

    /// The attribute has an unknown (integral) ID.
    #[error("unknown attribute ID")]
    UnknownAttributeId(#[from] TryFromPrimitiveError<AttributeId>),

    /// The attribute's ID doesn't match the format supplied.
    #[error("malformed attribute (format doesn't match ID): {0}: {1:?}")]
    AttributeMalformed(&'static str, AttributeId),

    /// We recognize the attribute's ID as an integer attribute, but we don't support it yet.
    #[error("FIXME: unsupported integer attribute: {0:?}")]
    IntAttributeUnsupported(AttributeId),

    /// An entry record asked for a nonexistent attribute group.
    #[error("nonexistent attribute group: {0}")]
    BadAttributeGroup(u32),

    /// An attribute group record was too short.
    #[error("attribute group record for {0:?} too short ({1} < 3)")]
    GroupTooShort(AttributeCode, usize),

    /// Parsing an attribute group didn't fully consume the underlying record fields.
    #[error("under/overconsumed fields in attribute group record ({0} fields, {1} consumed)")]
    GroupSizeMismatch(usize, usize),

    /// A generic mapping error occured.
    #[error("mapping error in string table")]
    Map(#[from] MapError),
}

/// Represents the "enum" attributes, i.e. those with a single integer identifier.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u64)]
pub enum EnumAttribute {
    /// `alwaysinline`
    AlwaysInline = AttributeId::AlwaysInline as u64,
    /// `byval`
    ByVal = AttributeId::ByVal as u64,
    /// `inlinehint`
    InlineHint = AttributeId::InlineHint as u64,
    /// `inreg`
    InReg = AttributeId::InReg as u64,
    /// `minsize`
    MinSize = AttributeId::MinSize as u64,
    /// `naked`
    Naked = AttributeId::Naked as u64,
    /// `nest`
    Nest = AttributeId::Nest as u64,
    /// `noalias`
    NoAlias = AttributeId::NoAlias as u64,
    /// `nobuiltin`
    NoBuiltin = AttributeId::NoBuiltin as u64,
    /// `nocapture`
    NoCapture = AttributeId::NoCapture as u64,
    /// `noduplicate`
    NoDuplicate = AttributeId::NoDuplicate as u64,
    /// `noimplicitfloat`
    NoImplicitFloat = AttributeId::NoImplicitFloat as u64,
    /// `noinline`
    NoInline = AttributeId::NoInline as u64,
    /// `nonlazybind`
    NonLazyBind = AttributeId::NonLazyBind as u64,
    /// `noredzone`
    NoRedZone = AttributeId::NoRedZone as u64,
    /// `noreturn`
    NoReturn = AttributeId::NoReturn as u64,
    /// `nounwind`
    NoUnwind = AttributeId::NoUnwind as u64,
    /// `optsize`
    OptimizeForSize = AttributeId::OptimizeForSize as u64,
    /// `readnone`
    ReadNone = AttributeId::ReadNone as u64,
    /// `readonly`
    ReadOnly = AttributeId::ReadOnly as u64,
    /// `returned`
    Returned = AttributeId::Returned as u64,
    /// `returns_twice`
    ReturnsTwice = AttributeId::ReturnsTwice as u64,
    /// `signext`
    SExt = AttributeId::SExt as u64,
    /// `ssp`
    StackProtect = AttributeId::StackProtect as u64,
    /// `sspreq`
    StackProtectReq = AttributeId::StackProtectReq as u64,
    /// `sspstrong`
    StackProtectStrong = AttributeId::StackProtectStrong as u64,
    /// `sret`
    StructRet = AttributeId::StructRet as u64,
    /// `sanitize_address`
    SanitizeAddress = AttributeId::SanitizeAddress as u64,
    /// `sanitize_thread`
    SanitizeThread = AttributeId::SanitizeThread as u64,
    /// `sanitize_memory`
    SanitizeMemory = AttributeId::SanitizeMemory as u64,
    /// `uwtable`
    UwTable = AttributeId::UwTable as u64,
    /// `zeroext`
    ZExt = AttributeId::ZExt as u64,
    /// `builtin`
    Builtin = AttributeId::Builtin as u64,
    /// `cold`
    Cold = AttributeId::Cold as u64,
    /// `optnone`
    OptimizeNone = AttributeId::OptimizeNone as u64,
    /// `inalloca`
    InAlloca = AttributeId::InAlloca as u64,
    /// `nonnull`
    NonNull = AttributeId::NonNull as u64,
    /// `jumptable`
    JumpTable = AttributeId::JumpTable as u64,
    /// `convergent`
    Convergent = AttributeId::Convergent as u64,
    /// `safestack`
    SafeStack = AttributeId::SafeStack as u64,
    /// `argmemonly`
    ArgMemOnly = AttributeId::ArgMemOnly as u64,
    /// `swiftself`
    SwiftSelf = AttributeId::SwiftSelf as u64,
    /// `swifterror`
    SwiftError = AttributeId::SwiftError as u64,
    /// `norecurse`
    NoRecurse = AttributeId::NoRecurse as u64,
    /// `inaccessiblememonly`
    InaccessiblememOnly = AttributeId::InaccessiblememOnly as u64,
    /// `inaccessiblememonly_or_argmemonly`
    InaccessiblememOrArgmemonly = AttributeId::InaccessiblememOrArgmemonly as u64,
    /// `writeonly`
    WriteOnly = AttributeId::WriteOnly as u64,
    /// `speculatable`
    Speculatable = AttributeId::Speculatable as u64,
    /// `strictfp`
    StrictFp = AttributeId::StrictFp as u64,
    /// `sanitize_hwaddress`
    SanitizeHwAddress = AttributeId::SanitizeHwAddress as u64,
    /// `nocf_check`
    NoCfCheck = AttributeId::NoCfCheck as u64,
    /// `optforfuzzing`
    OptForFuzzing = AttributeId::OptForFuzzing as u64,
    /// `shadowcallstack`
    ShadowCallStack = AttributeId::ShadowCallStack as u64,
    /// `speculative_load_hardening`
    SpeculativeLoadHardening = AttributeId::SpeculativeLoadHardening as u64,
    /// `immarg`
    ImmArg = AttributeId::ImmArg as u64,
    /// `willreturn`
    WillReturn = AttributeId::WillReturn as u64,
    /// `nofree`
    NoFree = AttributeId::NoFree as u64,
    /// `nosync`
    NoSync = AttributeId::NoSync as u64,
    /// `sanitize_memtag`
    SanitizeMemtag = AttributeId::SanitizeMemtag as u64,
    /// `preallocated`
    Preallocated = AttributeId::Preallocated as u64,
    /// `no_merge`
    NoMerge = AttributeId::NoMerge as u64,
    /// `null_pointer_is_valid`
    NullPointerIsValid = AttributeId::NullPointerIsValid as u64,
    /// `noundef`
    NoUndef = AttributeId::NoUndef as u64,
    /// `byref`
    ByRef = AttributeId::ByRef as u64,
    /// `mustprogress`
    MustProgress = AttributeId::MustProgress as u64,
    /// `no_callback`
    NoCallback = AttributeId::NoCallback as u64,
    /// `hot`
    Hot = AttributeId::Hot as u64,
    /// `no_profile`
    NoProfile = AttributeId::NoProfile as u64,
    /// `swift_async`
    SwiftAsync = AttributeId::SwiftAsync as u64,
    /// `nosanitize_coverage`
    NoSanitizeCoverage = AttributeId::NoSanitizeCoverage as u64,
    /// `elementtype`
    ElementType = AttributeId::ElementType as u64,
    /// `disable_sanitizer_instrumentation`
    DisableSanitizerInstrumentation = AttributeId::DisableSanitizerInstrumentation as u64,
    /// ``allocalign`
    AllocAlign = AttributeId::AllocAlign as u64,
    /// `allocptr`
    AllocatedPointer = AttributeId::AllocatedPointer as u64,
    /// `presplitcoroutine`
    PresplitCoroutine = AttributeId::PresplitCoroutine as u64,
    /// `fn_ret_thunk_extern`
    FnRetThunkExtern = AttributeId::FnRetThunkExtern as u64,
    /// `skipprofile`
    SkipProfile = AttributeId::SkipProfile as u64,
    /// Pointer argument is writable.
    ///
    /// `writable`
    Writable = AttributeId::Writable as u64,
    /// `dead_on_unwind`
    DeadOnUnwind = AttributeId::DeadOnUnwind as u64,
}

impl TryFrom<AttributeId> for EnumAttribute {
    type Error = AttributeError;

    fn try_from(value: AttributeId) -> Result<Self, Self::Error> {
        (value as u64)
            .try_into()
            .map_err(|_| AttributeError::AttributeMalformed("non-enum attribute ID given", value))
    }
}

/// Represent unwind table variant
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u64)]
pub enum UwTableVariant {
    /// No unwind table requested
    None = 0,
    /// Synchronous unwinding table
    Sync = 1,
    /// Asynchronous unwinding table
    Async = 2,
}

/// Represents an integral attribute, i.e. an attribute that carries (at least) one integer value with it.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IntAttribute {
    /// `align(<n>)`
    Alignment(MaybeAlign),
    /// `alignstack(<n>)`
    StackAlignment(MaybeAlign),
    /// `dereferenceable(<n>)`
    Dereferenceable(u64),
    /// `dereferenceable_or_null(<n>)`
    DereferenceableOrNull(u64),
    /// `allocsize(<EltSizeParam>[, <NumEltsParam>])`
    AllocSize(u32, Option<u32>),
    /// `vscale_range(<Min>[, <Max>])`
    VScaleRange(u32, u32),
    /// `uwTable ([variant])`
    UwTable(UwTableVariant),
    /// `allockind (<KindBitset>)`
    AllocKind(u64),
    /// `memory (<memoryEffectBitset>)`
    MemoryKind(u64),
}

impl TryFrom<(AttributeId, u64)> for IntAttribute {
    type Error = AttributeError;

    fn try_from((key, value): (AttributeId, u64)) -> Result<Self, Self::Error> {
        // Test if it's an enum attribute. If it is, we know it can't be an integer attribute
        // and any fallthrough in our match below is unsupported rather than malformed.
        // UwTable is special because it is both enum attribute and integer attirbute
        if EnumAttribute::try_from(key).is_ok() && key != AttributeId::UwTable {
            return Err(AttributeError::AttributeMalformed(
                "expected int attribute, but given enum ID",
                key,
            ));
        }

        Ok(match key {
            AttributeId::Alignment => {
                let value = u8::try_from(value).map_err(|_| {
                    AttributeError::AttributeMalformed(
                        "attribute value too large (invalid alignment)",
                        key,
                    )
                })?;

                IntAttribute::Alignment(
                    MaybeAlign::try_from(value).map_err(|_| {
                        AttributeError::AttributeMalformed("invalid alignment", key)
                    })?,
                )
            }
            AttributeId::StackAlignment => {
                let value = u8::try_from(value).map_err(|_| {
                    AttributeError::AttributeMalformed(
                        "attribute value too large (invalid alignment)",
                        key,
                    )
                })?;

                IntAttribute::StackAlignment(
                    MaybeAlign::try_from(value).map_err(|_| {
                        AttributeError::AttributeMalformed("invalid alignment", key)
                    })?,
                )
            }
            AttributeId::Dereferenceable => IntAttribute::Dereferenceable(value),
            AttributeId::DereferenceableOrNull => IntAttribute::DereferenceableOrNull(value),
            AttributeId::AllocSize => {
                if value == 0 {
                    return Err(AttributeError::AttributeMalformed(
                        "allocasize argument invalid: cannot be (0, 0)",
                        key,
                    ));
                }

                // NOTE(ww): This attribute isn't well documented. From reading the LLVM code:
                // * `value` can't be 0, but the upper 32 bits of `value` can be
                // * The lower 32 bits should be 0xFFFFFFFF (-1) if not present
                let elt_size = (value >> 32) as u32;
                let num_elts = match value as u32 {
                    u32::MAX => None,
                    num_elts => Some(num_elts),
                };

                IntAttribute::AllocSize(elt_size, num_elts)
            }
            AttributeId::VScaleRange => {
                let min = (value >> 32) as u32;
                let max = match value as u32 {
                    0 => min,
                    max => max,
                };

                IntAttribute::VScaleRange(max, min)
            }
            AttributeId::UwTable => {
                IntAttribute::UwTable(UwTableVariant::try_from(value).map_err(|_| {
                    AttributeError::AttributeMalformed("Unwind table variant error", key)
                })?)
            }
            AttributeId::AllocKind => IntAttribute::AllocKind(value),
            AttributeId::Memory => IntAttribute::MemoryKind(value),
            o => return Err(AttributeError::IntAttributeUnsupported(o)),
        })
    }
}

/// Represents a type attribute.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u64)]
pub enum TypeAttribute {
    /// Pass structure by value (`byval`).  
    ByVal = AttributeId::ByVal as u64,
    /// Mark in-memory ABI type (`byref`).
    ByRef = AttributeId::ByRef as u64,
    /// Provide pointer element type to intrinsic (`elementtype`).
    ElementType = AttributeId::ElementType as u64,
    /// Pass structure in an alloca (`inalloca`).
    InAlloca = AttributeId::InAlloca as u64,
    /// Similar to `byval` but without a copy (`preallocated`).
    Preallocated = AttributeId::Preallocated as u64,
    /// Hidden pointer to structure to return (`sret`).
    StructRet = AttributeId::StructRet as u64,
}

impl TryFrom<AttributeId> for TypeAttribute {
    type Error = AttributeError;

    fn try_from(value: AttributeId) -> Result<Self, Self::Error> {
        (value as u64)
            .try_into()
            .map_err(|_| AttributeError::AttributeMalformed("non-type attribute ID given", value))
    }
}

/// Represents an integer constant range attribute.
/// Although undocumented, this is PARAMMATR_GRP_CODE_ENTRY code 7.
///
/// See the LLVM Bitcode File Format's
/// [PARAMATTR_GRP_CODE_ENTRY Record](https://llvm.org/docs/BitCodeFormat.html#paramattr-grp-code-entry-record)
/// for more details.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstantRangeAttribute {
    /// Represent a range of possible values that may occur when the program is run
    /// for an integral value.  This keeps track of a lower and upper bound for the
    /// constant, which MAY wrap around the end of the numeric range.  To do this, it
    /// keeps track of a [lower, upper) bound, which specifies an interval just like
    /// STL iterators.  When used with boolean values, the following are important
    /// ranges: :
    ///
    ///  [F, F) = {}     = Empty set
    ///  [T, F) = {T}
    ///  [F, T) = {F}
    ///  [T, T) = {F, T} = Full set
    ///
    /// The other integral ranges use min/max values for special range values. For
    /// example, for 8-bit types, it uses:
    /// [0, 0)     = {}       = Empty set
    /// [255, 255) = {0..255} = Full Set
    ///
    /// Note that ConstantRange can be used to represent either signed or
    /// unsigned ranges.
    ///
    /// From llvm/IR/ConstantRange.h
    Range(ApInt, ApInt),
}

impl ConstantRangeAttribute {
    #[inline(always)]
    /// Decode a signed value stored with the sign bit in the LSB for dense
    /// VBR encoding.
    pub fn decode_sign_rotated_value(value: u64) -> u64 {
        if value & 1 == 0 {
            value >> 1
        } else if value != 1 {
            // C equivalent of -(V >> 1)
            !(value >> 1) + 1
        } else {
            // There is no such thing as -0 with integers. "-0" really means
            // MININT.
            (1 as u64) << 63
        }
    }

    #[inline]
    /// Decodes a slice of sign rotated words and collects them into an ApInt.
    pub fn read_wide_ap_int(values: &[u64]) -> ApInt {
        let words = values
            .iter()
            .map(|&v| Self::decode_sign_rotated_value(v))
            .collect::<Vec<u64>>();

        slice_to_apint!(u64, words.as_slice())
    }
}

impl TryFrom<(&mut usize, AttributeId, u64, &[u64])> for ConstantRangeAttribute {
    type Error = AttributeError;

    fn try_from(
        (field_count, key, bit_width, mut data): (&mut usize, AttributeId, u64, &[u64]),
    ) -> Result<Self, Self::Error> {
        use ConstantRangeAttribute as Impl;

        match key {
            // See BitcodeReader::readConstantRange in llvm/Bitcode/Reader.cpp
            // for LLVM implementation
            AttributeId::Range => {
                // Too few records for range
                if data.len() < 2 {
                    return Err(AttributeError::TooShort);
                }

                let (start, end) = if bit_width > 64 {
                    // Retrieve the count of active lower and upper words
                    let lo_words = data[0] as usize;
                    let hi_words = (data[1] >> 32) as usize;
                    *field_count += 2;

                    // Advance records and check for the next  lower and upper
                    // word records
                    data = &data[2..];
                    if data.len() < lo_words + hi_words {
                        return Err(AttributeError::TooShort);
                    }

                    let lower = Impl::read_wide_ap_int(&data[..lo_words]);
                    let upper = Impl::read_wide_ap_int(&data[lo_words..lo_words + hi_words]);
                    *field_count += lo_words + hi_words;

                    (lower, upper)
                }
                // The data range is encoded within the next two fields
                else {
                    // Read then decode the next two values, and keep track of
                    // the field offset.
                    let start = Impl::decode_sign_rotated_value(data[0]).into();
                    let end = Impl::decode_sign_rotated_value(data[1]).into();
                    *field_count += 2;

                    (start, end)
                };

                Ok(Impl::Range(start, end))
            }
            id => Err(AttributeError::IntAttributeUnsupported(id)),
        }
    }
}

/// Represents a single, concrete LLVM attribute.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribute {
    /// An enumerated attribute.
    Enum(EnumAttribute),
    /// An integer attribute.
    Int(IntAttribute),
    /// An arbitrary string attribute.
    Str(String),
    /// An arbitrary string attribute with a string value.
    StrKeyValue(String, String),
    /// A range of possible values that may occur when a program is run for an
    /// integral value.
    ConstantRange(ConstantRangeAttribute),
}

impl Attribute {
    /// Parse a new `Attribute` from the given record at the given start index, returning
    /// a tuple of the number of fields consumed and the parsed result.
    fn from_record(start: usize, record: &Record) -> Result<(usize, Self), AttributeError> {
        let mut fieldcount = 0;

        // You might ask: why are these macros?
        // I originally wrote them as clever little locally-capturing lambdas, but
        // having both mutate their closure confused the borrow checker.
        // Writing them as macros lets everything expand inline, keeping the checker happy.
        macro_rules! next {
            () => {
                if let Some(field) = record.fields().get(start + fieldcount) {
                    fieldcount += 1;
                    Ok(*field)
                } else {
                    Err(AttributeError::TooShort)
                }
            };
        }

        macro_rules! take_string {
            // NOTE(ww): Weird double-brace to make sure the macro expands as a full expression.
            () => {{
                let str_bytes = record.fields()[start + fieldcount..]
                    .iter()
                    .take_while(|f| **f != 0)
                    .map(|f| u8::try_from(*f))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| AttributeError::BadString)?;

                if str_bytes.is_empty() {
                    Err(AttributeError::BadString)
                } else {
                    let result =
                        String::from_utf8(str_bytes).map_err(|_| AttributeError::BadString)?;

                    // NOTE(ww): plus one to include the NULL byte that we consumed above.
                    fieldcount += result.as_bytes().len() + 1;

                    Ok(result)
                }
            }};
        }

        // Each attribute's fields look like this:
        //  [kind, key[...], [value[...]]]
        // ...where `kind` indicates the general attribute structure
        // (integral or string, single-value or key-value).
        let kind_id = next!()?;

        let kind = AttributeKind::try_from(kind_id)
            .inspect_err(|e| log::error!("failed to resolve attribute kind of {}", e.number))?;

        let attribute = match kind {
            AttributeKind::Enum => {
                // Enum attributes: one key field, nothing else.
                let key = AttributeId::try_from(next!()?)?;
                // TODO: deal with UwTable attribute's default value
                Ok((fieldcount, Attribute::Enum(key.try_into()?)))
            }
            AttributeKind::IntKeyValue => {
                // Integer key-value attributes: one key, one integer value.
                let key = AttributeId::try_from(next!()?)?;
                let value = next!()?;

                Ok((fieldcount, Attribute::Int(TryInto::try_into((key, value))?)))
            }
            AttributeKind::StrKey => {
                // String attributes: one string key field, nothing else.
                let key = take_string!()?;

                Ok((fieldcount, Attribute::Str(key)))
            }
            AttributeKind::StrKeyValue => {
                // String key-value attributes: one string key field, one string value field.
                let key = take_string!()?;
                let value = take_string!()?;

                Ok((fieldcount, Attribute::StrKeyValue(key, value)))
            }
            AttributeKind::ConstantRange => {
                let key = AttributeId::try_from(next!()?)?;
                let bit_width = next!()?;
                let words = &record.fields()[start..start + fieldcount];

                let res = Attribute::ConstantRange(TryInto::try_into((
                    &mut fieldcount,
                    key,
                    bit_width,
                    words,
                ))?);

                Ok((fieldcount, res))
            }
            AttributeKind::ConstantRangeList => {
                unimplemented!()
            }
        };

        // Show what the attributes resolve to, only in debug mode for
        // performance.
        #[cfg(debug_assertions)]
        if let Some((_, attr)) = attribute.as_ref().ok() {
            log::debug!("attribute {} resolves to {:?}", kind_id, attr);
        } else {
            log::debug!("failed to resolve attribute {}", kind_id);
        };

        attribute
    }
}

/// Represents all of the [`AttributeGroup`](AttributeGroup)s associated with some function.
#[derive(Debug)]
pub struct AttributeEntry(Vec<AttributeGroup>);

/// Maps all attributes in an IR module.
#[derive(Debug, Default)]
pub struct Attributes(Vec<AttributeEntry>);

impl Attributes {
    pub(crate) fn get(&self, id: u64) -> Option<&AttributeEntry> {
        self.0.get(id as usize)
    }
}

impl TryFrom<(&'_ Block, &'_ PartialMapCtx)> for Attributes {
    type Error = AttributeError;

    fn try_from((block, ctx): (&'_ Block, &'_ PartialMapCtx)) -> Result<Self, Self::Error> {
        let mut entries = vec![];

        for record in &block.records {
            let code = AttributeCode::try_from(record.code()).map_err(AttributeError::from)?;

            match code {
                AttributeCode::EntryOld => {
                    unimplemented!();
                }
                AttributeCode::Entry => {
                    let mut groups = vec![];
                    for group_id in record.fields() {
                        let group_id = *group_id as u32;
                        log::debug!("group id: {}", group_id);
                        groups.push(
                            ctx.attribute_groups()
                                .get(group_id)
                                .ok_or(AttributeError::BadAttributeGroup(group_id))?
                                .clone(),
                        );
                    }
                    entries.push(AttributeEntry(groups));
                }
                AttributeCode::GroupCodeEntry => {
                    // This is a valid attribute code, but it isn't valid in this block.
                    return Err(AttributeError::WrongBlock(code));
                }
            }
        }

        Ok(Attributes(entries))
    }
}

/// Represents the "disposition" of an attribute group, i.e. whether its attributes
/// are associated with the return value, specific parameters, or the entire associated function.
#[derive(Clone, Copy, Debug)]
pub enum AttributeGroupDisposition {
    /// The associated attributes are return value attributes.
    Return,
    /// The associated attributes are parameter attributes (1-indexed).
    Parameter(u32),
    /// The associated attributes are function attributes.
    Function,
}

impl From<u32> for AttributeGroupDisposition {
    fn from(value: u32) -> Self {
        match value {
            u32::MAX => Self::Function,
            0 => Self::Return,
            _ => Self::Parameter(value),
        }
    }
}

/// Represents a single attribute group.
#[derive(Clone, Debug)]
pub struct AttributeGroup {
    /// The "disposition" of this attribute group.
    pub disposition: AttributeGroupDisposition,
    /// The attributes in this group.
    pub attributes: Vec<Attribute>,
}

/// Maps all attribute groups in an IR module.
#[derive(Debug, Default)]
pub struct AttributeGroups(HashMap<u32, AttributeGroup>);

impl AttributeGroups {
    pub(crate) fn get(&self, group_id: u32) -> Option<&AttributeGroup> {
        self.0.get(&group_id)
    }
}

impl TryFrom<&'_ Block> for AttributeGroups {
    type Error = AttributeError;

    fn try_from(block: &'_ Block) -> Result<Self, Self::Error> {
        let mut groups = HashMap::new();

        for record in &block.records {
            let code = AttributeCode::try_from(record.code()).map_err(AttributeError::from)?;

            if code != AttributeCode::GroupCodeEntry {
                return Err(AttributeError::WrongBlock(code));
            }

            // Structure: [grpid, paramidx, <attr0>, <attr1>, ...]
            // Every group record must have at least one attribute.
            if record.fields().len() < 3 {
                return Err(AttributeError::GroupTooShort(code, record.fields().len()));
            }

            // Panic safety: We check for at least three fields above.
            let group_id = record.fields()[0] as u32;
            let disposition: AttributeGroupDisposition = (record.fields()[1] as u32).into();

            // Each attribute in the group can potentially span multiple fields
            // in the record. Keep track of our field index to ensure that we
            // fully consume the records into a list of attributes.
            let mut fieldidx = 2;
            let mut attributes = vec![];
            while fieldidx < record.fields().len() {
                // debug!("{:#?}", groups);
                let (count, attr) = Attribute::from_record(fieldidx, record)?;
                attributes.push(attr);
                fieldidx += count;
            }

            // Sanity check: we should have consumed every single record.
            if fieldidx != record.fields().len() {
                return Err(AttributeError::GroupSizeMismatch(
                    fieldidx,
                    record.fields().len(),
                ));
            }

            groups.insert(
                group_id,
                AttributeGroup {
                    disposition,
                    attributes,
                },
            );
        }

        Ok(AttributeGroups(groups))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_sign_rotated_value() {
        const V1: u64 = 5;
        const V2: u64 = 224;

        let d1 = ConstantRangeAttribute::decode_sign_rotated_value(V1);
        let d2 = ConstantRangeAttribute::decode_sign_rotated_value(V2);

        assert_eq!(d1, 18446744073709551614);
        assert_eq!(d2, 112);
        assert_eq!(d1 as i64, -2);
        assert_eq!(d2 as i64, 112);
    }
}
