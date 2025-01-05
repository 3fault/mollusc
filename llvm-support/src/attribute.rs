//! Support code for LLVM attributes.

use num_enum::TryFromPrimitive;

/// Represents the different kinds of attributes.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u64)]
pub enum AttributeKind {
    /// A well-known enum attribute.
    Enum = 0,
    /// A well-known integral attribute with an integer value.
    IntKeyValue = 1,
    /// A string attribute.
    StrKey = 3,
    /// A string attribute with a string value.
    StrKeyValue = 4,
    /// TODO: Document
    UnknownAttribute5 = 5,
    /// TODO: Document
    UnknownAttributeWithType = 6,
    /// A constant range attribute.
    ConstantRange = 7,
    /// A constant range list attribute.
    ConstantRangeList = 8,
}

/// Represents the IDs of different specific attributes.
//
//  From llvm/Bitcode/LLVMBitCodes.h
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u64)]
pub enum AttributeId {
    /// Alignment of parameter (5 bits) stored as log2 of alignment with +1 bias.
    /// 0 means unaligned (different from align(1)).
    ///
    /// `align(<n>)`
    #[doc(alias = "ATTR_KIND_ALIGNMENT")]
    Alignment = 1,

    /// inline=always.
    ///
    /// `alwaysinline`
    #[doc(alias = "ATTR_KIND_ALWAYS_INLINE")]
    AlwaysInline = 2,

    /// Pass structure by value.
    ///
    /// `byval`
    #[doc(alias = "ATTR_KIND_BY_VAL")]
    ByVal = 3,

    /// Source said inlining was desirable.
    ///
    /// `inlinehint`
    #[doc(alias = "ATTR_KIND_INLINE_HINT")]
    InlineHint = 4,

    /// Force argument to be passed in register.
    ///
    /// `inreg`
    #[doc(alias = "ATTR_KIND_IN_REG")]
    InReg = 5,

    /// Function must be optimized for size first.
    ///
    /// `minsize`
    #[doc(alias = "ATTR_KIND_MIN_SIZE")]
    MinSize = 6,

    /// Naked function.
    ///
    /// `naked`
    #[doc(alias = "ATTR_KIND_NAKED")]
    Naked = 7,

    /// Nested function static chain.
    ///
    /// `nest`
    #[doc(alias = "ATTR_KIND_NEST")]
    Nest = 8,

    /// Considered to not alias after call.
    ///
    /// `noalias`
    #[doc(alias = "ATTR_KIND_NO_ALIAS")]
    NoAlias = 9,

    /// Callee isn't recognized as a builtin.
    ///
    /// `nobuiltin`
    #[doc(alias = "ATTR_KIND_NO_BUILTIN")]
    NoBuiltin = 10,

    /// Function creates no aliases of pointer.
    ///
    /// `nocapture`
    #[doc(alias = "ATTR_KIND_NO_CAPTURE")]
    NoCapture = 11,

    /// Call cannot be duplicated.
    ///
    /// `noduplicate`
    #[doc(alias = "ATTR_KIND_NO_DUPLICATE")]
    NoDuplicate = 12,

    /// Disable implicit floating point insts.
    ///
    /// `noimplicitfloat`
    #[doc(alias = "ATTR_KIND_NO_IMPLICIT_FLOAT")]
    NoImplicitFloat = 13,

    /// inline=never.
    ///
    /// `noinline`
    #[doc(alias = "ATTR_KIND_NO_INLINE")]
    NoInline = 14,

    /// Function is called early and/or often, so lazy binding isn't worthwhile.
    ///
    /// `nonlazybind`
    #[doc(alias = "ATTR_KIND_NON_LAZY_BIND")]
    NonLazyBind = 15,

    /// Disable redzone.
    ///
    /// `noredzone`
    #[doc(alias = "ATTR_KIND_NO_RED_ZONE")]
    NoRedZone = 16,

    /// Mark the function as not returning.
    ///
    /// `noreturn`
    #[doc(alias = "ATTR_KIND_NO_RETURN")]
    NoReturn = 17,

    /// Function doesn't unwind stack.
    ///
    /// `nounwind`
    #[doc(alias = "ATTR_KIND_NO_UNWIND")]
    NoUnwind = 18,

    /// opt_size.
    ///
    /// `optsize`
    #[doc(alias = "ATTR_KIND_OPTIMIZE_FOR_SIZE")]
    OptimizeForSize = 19,

    /// Function does not access memory.
    ///
    /// `readnone`
    #[doc(alias = "ATTR_KIND_READ_NONE")]
    ReadNone = 20,

    /// Function only reads from memory.
    ///
    /// `readonly`
    #[doc(alias = "ATTR_KIND_READ_ONLY")]
    ReadOnly = 21,

    /// Return value is always equal to this argument.
    ///
    /// `returned`
    #[doc(alias = "ATTR_KIND_RETURNED")]
    Returned = 22,

    /// Function can return twice.
    ///
    /// `returns_twice`
    #[doc(alias = "ATTR_KIND_RETURNS_TWICE")]
    ReturnsTwice = 23,

    /// Sign extended before/after call.
    ///
    /// `signext`
    #[doc(alias = "ATTR_KIND_S_EXT")]
    SExt = 24,

    /// Alignment of stack for function (3 bits)  stored as log2 of alignment with
    /// +1 bias 0 means unaligned (different from alignstack=(1)).
    ///
    /// `alignstack(<n>)`
    #[doc(alias = "ATTR_KIND_STACK_ALIGNMENT")]
    StackAlignment = 25,

    /// Stack protection.
    ///
    /// `ssp`
    #[doc(alias = "ATTR_KIND_STACK_PROTECT")]
    StackProtect = 26,

    /// Stack protection required.
    ///
    /// `sspreq`
    #[doc(alias = "ATTR_KIND_STACK_PROTECT_REQ")]
    StackProtectReq = 27,

    /// Strong Stack protection.
    ///
    /// `sspstrong`
    #[doc(alias = "ATTR_KIND_STACK_PROTECT_STRONG")]
    StackProtectStrong = 28,

    /// Hidden pointer to structure to return.
    ///
    /// `sret`
    #[doc(alias = "ATTR_KIND_STRUCT_RET")]
    StructRet = 29,

    /// AddressSanitizer is on.
    ///
    /// `sanitize_address`
    #[doc(alias = "ATTR_KIND_SANITIZE_ADDRESS")]
    SanitizeAddress = 30,

    /// ThreadSanitizer is on.
    ///
    /// `sanitize_thread`
    #[doc(alias = "ATTR_KIND_SANITIZE_THREAD")]
    SanitizeThread = 31,

    /// MemorySanitizer is on.
    ///
    /// `sanitize_memory`
    #[doc(alias = "ATTR_KIND_SANITIZE_MEMORY")]
    SanitizeMemory = 32,

    /// Function must be in a unwind table.
    ///
    /// `uwtable ([variant])`
    #[doc(alias = "ATTR_KIND_UW_TABLE")]
    UwTable = 33,

    /// Zero extended before/after call.
    ///
    /// `zeroext`
    #[doc(alias = "ATTR_KIND_Z_EXT")]
    ZExt = 34,

    /// Callee is recognized as a builtin, despite nobuiltin attribute on its
    /// declaration.
    ///
    /// `builtin`
    #[doc(alias = "ATTR_KIND_BUILTIN")]
    Builtin = 35,

    /// Marks function as being in a cold path.
    ///
    /// `cold`
    #[doc(alias = "ATTR_KIND_COLD")]
    Cold = 36,

    /// Function must not be optimized.
    ///
    /// `optnone`
    #[doc(alias = "ATTR_KIND_OPTIMIZE_NONE")]
    OptimizeNone = 37,

    /// Pass structure in an alloca.
    ///
    /// `inalloca`
    #[doc(alias = "ATTR_KIND_IN_ALLOCA")]
    InAlloca = 38,

    /// Pointer is known to be not null.
    ///
    /// `nonnull`
    #[doc(alias = "ATTR_KIND_NON_NULL")]
    NonNull = 39,

    /// Build jump-instruction tables and replace refs.
    ///
    /// `jumptable`
    #[doc(alias = "ATTR_KIND_JUMP_TABLE")]
    JumpTable = 40,

    /// Pointer is known to be dereferenceable.
    ///
    /// `dereferenceable(<n>)`
    #[doc(alias = "ATTR_KIND_DEREFERENCEABLE")]
    Dereferenceable = 41,

    /// Pointer is either null or dereferenceable.
    ///
    /// `dereferenceable_or_null(<n>)`
    #[doc(alias = "ATTR_KIND_DEREFERENCEABLE_OR_NULL")]
    DereferenceableOrNull = 42,

    /// Can only be moved to control-equivalent blocks.
    /// NB: Could be IntersectCustom with "or" handling.
    ///
    /// `convergent`
    #[doc(alias = "ATTR_KIND_CONVERGENT")]
    Convergent = 43,

    /// Safe Stack protection.
    ///
    /// `safestack`
    #[doc(alias = "ATTR_KIND_SAFESTACK")]
    SafeStack = 44,

    ///
    /// `argmemonly`
    #[doc(alias = "ATTR_KIND_ARGMEMONLY")]
    ArgMemOnly = 45,

    /// Argument is swift self/context.
    ///
    /// `swiftself`
    #[doc(alias = "ATTR_KIND_SWIFT_SELF")]
    SwiftSelf = 46,

    /// Argument is swift error.
    ///
    /// `swifterror`
    #[doc(alias = "ATTR_KIND_SWIFT_ERROR")]
    SwiftError = 47,

    /// The function does not recurse.
    ///
    /// `norecurse`
    #[doc(alias = "ATTR_KIND_NO_RECURSE")]
    NoRecurse = 48,

    /// `inaccessiblememonly`
    #[doc(alias = "ATTR_KIND_INACCESSIBLEMEM_ONLY")]
    InaccessiblememOnly = 49,

    /// `inaccessiblememonly_or_argmemonly`
    #[doc(alias = "ATTR_KIND_INACCESSIBLEMEM_OR_ARGMEMONLY")]
    InaccessiblememOrArgmemonly = 50,

    /// The result of the function is guaranteed to point to a number of bytes that
    /// we can determine if we know the value of the function's arguments.
    ///
    /// `allocsize(<EltSizeParam>[, <NumEltsParam>])`
    #[doc(alias = "ATTR_KIND_ALLOC_SIZE")]
    AllocSize = 51,

    /// Function only writes to memory.
    ///
    /// `writeonly`
    #[doc(alias = "ATTR_KIND_WRITEONLY")]
    WriteOnly = 52,

    /// Function can be speculated.
    ///
    /// `speculatable`
    #[doc(alias = "ATTR_KIND_SPECULATABLE")]
    Speculatable = 53,

    /// Function was called in a scope requiring strict floating point semantics.
    ///
    /// `strictfp`
    #[doc(alias = "ATTR_KIND_STRICT_FP")]
    StrictFp = 54,

    /// HWAddressSanitizer is on.
    ///
    /// `sanitize_hwaddress`
    #[doc(alias = "ATTR_KIND_SANITIZE_HWADDRESS")]
    SanitizeHwAddress = 55,

    /// Disable Indirect Branch Tracking.
    ///
    /// `nocf_check`
    #[doc(alias = "ATTR_KIND_NOCF_CHECK")]
    NoCfCheck = 56,

    /// Select optimizations for best fuzzing signal.
    ///
    /// `optforfuzzing`
    #[doc(alias = "ATTR_KIND_OPT_FOR_FUZZING")]
    OptForFuzzing = 57,

    /// Shadow Call Stack protection.
    ///
    /// `shadowcallstack`
    #[doc(alias = "ATTR_KIND_SHADOWCALLSTACK")]
    ShadowCallStack = 58,

    /// Speculative Load Hardening is enabled.
    ///
    /// Note that this uses the default compatibility (always compatible during
    /// inlining) and a conservative merge strategy where inlining an attributed
    /// body will add the attribute to the caller. This ensures that code carrying
    /// this attribute will always be lowered with hardening enabled.
    ///
    /// `speculative_load_hardening`
    #[doc(alias = "ATTR_KIND_SPECULATIVE_LOAD_HARDENING")]
    SpeculativeLoadHardening = 59,

    /// Parameter is required to be a trivial constant.
    ///
    /// `immarg`
    #[doc(alias = "ATTR_KIND_IMMARG")]
    ImmArg = 60,

    /// Function always comes back to callsite.
    ///
    /// `willreturn`
    #[doc(alias = "ATTR_KIND_WILLRETURN")]
    WillReturn = 61,

    /// Function does not deallocate memory.
    ///
    /// `nofree`
    #[doc(alias = "ATTR_KIND_NOFREE")]
    NoFree = 62,

    /// Function does not synchronize.
    ///
    /// `nosync`
    #[doc(alias = "ATTR_KIND_NOSYNC")]
    NoSync = 63,

    /// MemTagSanitizer is on.
    ///
    /// `sanitize_memtag`
    #[doc(alias = "ATTR_KIND_SANITIZE_MEMTAG")]
    SanitizeMemtag = 64,

    /// Similar to byval but without a copy.
    ///
    /// `preallocated`
    #[doc(alias = "ATTR_KIND_PREALLOCATED")]
    Preallocated = 65,

    /// Disable merging for specified functions or call sites.
    ///
    /// `no_merge`
    #[doc(alias = "ATTR_KIND_NO_MERGE")]
    NoMerge = 66,

    /// Null pointer in address space zero is valid.
    ///
    /// `null_pointer_is_valid`
    #[doc(alias = "ATTR_KIND_NULL_POINTER_IS_VALID")]
    NullPointerIsValid = 67,

    /// Parameter or return value may not contain uninitialized or poison bits.
    ///
    /// `noundef`
    #[doc(alias = "ATTR_KIND_NOUNDEF")]
    NoUndef = 68,

    /// Mark in-memory ABI type.
    ///
    /// `byref`
    #[doc(alias = "ATTR_KIND_BYREF")]
    ByRef = 69,

    ///
    /// `mustprogress`
    #[doc(alias = "ATTR_KIND_MUSTPROGRESS")]
    MustProgress = 70,

    ///
    /// `no_callback`
    #[doc(alias = "ATTR_KIND_NO_CALLBACK")]
    NoCallback = 71,

    /// Marks function as being in a hot path and frequently called.
    ///
    /// `hot`
    #[doc(alias = "ATTR_KIND_HOT")]
    Hot = 72,

    /// Function should not be instrumented.
    ///
    /// `no_profile`
    #[doc(alias = "ATTR_KIND_NO_PROFILE")]
    NoProfile = 73,

    /// Minimum/Maximum vscale value for function.
    ///
    /// `vscale_range(<Min>[, <Max>])`
    #[doc(alias = "ATTR_KIND_VSCALE_RANGE")]
    VScaleRange = 74,

    /// Argument is swift async context.
    ///
    /// `swift_async`
    #[doc(alias = "ATTR_KIND_SWIFT_ASYNC")]
    SwiftAsync = 75,

    /// No SanitizeCoverage instrumentation.
    ///
    /// `nosanitize_coverage`
    #[doc(alias = "ATTR_KIND_NO_SANITIZE_COVERAGE")]
    NoSanitizeCoverage = 76,

    /// Provide pointer element type to intrinsic.
    ///
    /// `elementtype`
    #[doc(alias = "ATTR_KIND_ELEMENTTYPE")]
    ElementType = 77,

    /// Do not instrument function with sanitizers.
    ///
    /// `disable_sanitizer_instrumentation`
    #[doc(alias = "ATTR_KIND_DISABLE_SANITIZER_INSTRUMENTATION")]
    DisableSanitizerInstrumentation = 78,

    /// No SanitizeBounds instrumentation.
    ///
    /// `nosanitize_bounds`
    #[doc(alias = "ATTR_KIND_NO_SANITIZE_BOUNDS")]
    NoSanitizeBounds = 79,

    /// Parameter of a function that tells us the alignment of an allocation, as in
    /// aligned_alloc and aligned ::operator::new.
    ///
    /// `allocalign`
    #[doc(alias = "ATTR_KIND_ALLOC_ALIGN")]
    AllocAlign = 80,

    /// Parameter is the pointer to be manipulated by the allocator function.
    ///
    /// `allocptr`
    #[doc(alias = "ATTR_KIND_ALLOCATED_POINTER")]
    AllocatedPointer = 81,

    /// Describes behavior of an allocator function in terms of known properties.
    ///
    /// `allockind (<KindBitset>)`
    #[doc(alias = "ATTR_KIND_ALLOC_KIND")]
    AllocKind = 82,

    /// Function is a presplit coroutine.
    ///
    /// `presplitcoroutine`
    #[doc(alias = "ATTR_KIND_PRESPLIT_COROUTINE")]
    PresplitCoroutine = 83,

    /// Whether to keep return instructions, or replace with a jump to an external
    /// symbol.
    ///
    /// `fn_ret_thunk_extern`
    #[doc(alias = "ATTR_KIND_FNRETTHUNK_EXTERN")]
    FnRetThunkExtern = 84,

    /// This function should not be instrumented but it is ok to inline profiled
    // functions into it.
    ///
    /// `skipprofile`
    #[doc(alias = "ATTR_KIND_SKIP_PROFILE")]
    SkipProfile = 85,

    /// Memory effects of the function.
    ///
    /// `memory`
    #[doc(alias = "ATTR_KIND_MEMORY")]
    Memory = 86,

    /// Forbidden floating-point classes.
    ///
    /// `nofpclass`
    #[doc(alias = "ATTR_KIND_NOFPCLASS")]
    NoFpClass = 87,

    /// Select optimizations that give decent debug info.
    ///
    /// `optdebug`
    #[doc(alias = "ATTR_KIND_OPTIMIZE_FOR_DEBUGGING")]
    OptimizeForDebugging = 88,

    /// Pointer argument is writable.
    ///
    /// `writable`
    #[doc(alias = "ATTR_KIND_WRITABLE")]
    Writable = 89,

    /// The coroutine would only be destroyed when it is complete.
    ///
    /// `coro_only_destroy_when_complete`
    #[doc(alias = "ATTR_KIND_CORO_ONLY_DESTROY_WHEN_COMPLETE")]
    CoroOnlyDestroyWhenComplete = 90,

    /// Argument is dead if the call unwinds.
    ///
    /// `dead_on_unwind`
    #[doc(alias = "ATTR_KIND_DEAD_ON_UNWIND")]
    DeadOnUnwind = 91,

    /// Parameter or return value is within the specified range.
    ///
    /// `range`
    #[doc(alias = "ATTR_KIND_RANGE")]
    Range = 92,

    /// NumericalStabilitySanitizer is on.
    ///
    /// `sanitize_numerical_stability`
    #[doc(alias = "ATTR_KIND_SANITIZE_NUMERICAL_STABILITY")]
    SanitizeNumericalStability = 93,

    /// Pointer argument memory is initialized.
    ///
    /// `initializes`
    #[doc(alias = "ATTR_KIND_INITIALIZES")]
    Initializes = 94,

    /// Function has a hybrid patchable thunk.
    ///
    /// `hybrid_patchable`
    #[doc(alias = "ATTR_KIND_HYBRID_PATCHABLE")]
    HybridPatchable = 95,

    /// RealtimeSanitizer is on.
    ///
    /// `sanitize_realtime`
    #[doc(alias = "ATTR_KIND_SANITIZE_REALTIME")]
    SanitizeRealtime = 96,

    /// RealtimeSanitizer should error if a real-time unsafe function is invoked
    /// during a real-time sanitized function (see `sanitize_realtime`).
    ///
    /// `sanitize_realtime_blocking`
    #[doc(alias = "ATTR_KIND_SANITIZE_REALTIME_BLOCKING")]
    SanitizeRealtimeBlocking = 97,

    /// The coroutine call meets the elide requirement. Hint the optimization
    /// pipeline to perform elide on the call or invoke instruction.
    ///
    /// `coro_elide_safe`
    #[doc(alias = "ATTR_KIND_CORO_ELIDE_SAFE")]
    CoroElideSafe = 98,

    /// No extension needed before/after call (high bits are undefined).
    ///
    /// `noext`
    #[doc(alias = "ATTR_KIND_NO_EXT")]
    NoExt = 99,

    /// Function is not a source of divergence.
    ///
    /// `nodivergencesource`
    #[doc(alias = "ATTR_KIND_NO_DIVERGENCE_SOURCE")]
    NoDivergenceSource = 100,

    /// TypeSanitizer is on.
    ///
    /// `sanitize_type`
    #[doc(alias = "ATTR_KIND_SANITIZE_TYPE")]
    SanitizeType = 101,
}
