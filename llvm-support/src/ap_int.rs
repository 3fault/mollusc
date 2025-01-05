//! TODO: Document

#[macro_export]
/// TODO: Document
macro_rules! slice_to_apint {
    // Coerces a slice of LEN into an array of [T; N]
    // for arrays where ApInt has implemented From<[T;N]>
    //
    // The compiler should ommit the check for the
    // try_into as the coercion is Infallible, so the
    // call to unwrap() should never panic
    (@to_array $T:ty, $LEN:expr, $target:expr) => {
        <[$T; $LEN] as Into<$crate::ApInt>>::into(
            *TryInto::<&[$T; $LEN]>::try_into($target).unwrap(),
        )
    };

    (@match, $T:ty, $var:expr) => {
        // if !matches!($var.len(), 2..8 | 16 | 32) { unimplemented!("...") }
        match $var.len() {
            2 => slice_to_apint!(@to_array $T, 2, $var),
            3 => slice_to_apint!(@to_array $T, 3, $var),
            4 => slice_to_apint!(@to_array $T, 4, $var),
            5 => slice_to_apint!(@to_array $T, 5, $var),
            6 => slice_to_apint!(@to_array $T, 6, $var),
            7 => slice_to_apint!(@to_array $T, 7, $var),
            8 => slice_to_apint!(@to_array $T, 8, $var),
            16 => slice_to_apint!(@to_array $T, 16, $var),
            32 => slice_to_apint!(@to_array $T, 32, $var),
            _ => unimplemented!("ApInt does not implement From<[{}; {}]>", stringify!($T), $var.len()),
        }
    };

    (@assert_type $x:ty, $($xs:ty),+ $(,)*) => {
        const _: fn() = || {
            trait TypeEq {
                type This: ?Sized;
            }

            impl<T: ?Sized> TypeEq for T {
                type This = Self;
            }

            fn assert_type_eq_all<T, U>()
            where
                T: ?Sized + TypeEq<This = U>,
                U: ?Sized,
            {}

            // TODO: switch to assert_type_eq_ne
            $({assert_type_eq_all::<$x, $xs>()})+;
         };
    };

    // ApInt implements From<[(u64 | u32); LEN]> for lens of (2..8 | 16 | 32)
    ($T:ty, $var:expr) => {{
        slice_to_apint!(@assert_type $T, u64);
        slice_to_apint!(@match, $T, $var)
    }};
}
