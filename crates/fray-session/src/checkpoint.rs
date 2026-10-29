//! Pure support for existing canonical game and migration images.
//!
//! These are the unchanged bounded codecs, finite-number audit and migration
//! image hash. Authority state hashing uses its own domain in `authority`.
//! This module contains no signatures, random sampling, I/O or clock reads.

use sha2::{Digest as _, Sha256};
use std::fmt;

pub type Hash = [u8; 32];
pub const MAX_IMAGE: usize = 1024 * 1024;
pub const MAX_BATCH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Bounds,
    /// Frame was not consumed; defer it through a bounded ReceiveQueue.
    RateLimited,
    Unauthorized,
    Stale,
    Closed,
    Conflict,
    Gap,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

fn hash(label: &[u8], bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(label);
    h.update(bytes);
    h.finalize().into()
}
pub fn state_hash(bytes: &[u8]) -> Result<Hash> {
    if bytes.len() > MAX_IMAGE {
        return Err(Error::Bounds);
    }
    Ok(hash(b"fray/migration/state/v1\0", bytes))
}
/// Audit every serialized numeric leaf before accepting an authority image.
/// Game-specific sentinels must have an explicit codec (for example an absent
/// deadline), so malformed NaNs/infinities cannot hide inside nested state.
pub fn validate_finite<T: serde::Serialize + ?Sized>(value: &T) -> Result<()> {
    value.serialize(number_check::Check)
}
mod number_check {
    use super::*;
    use serde::ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant, Serializer,
    };
    #[derive(Clone, Copy)]
    pub(super) struct Check;
    impl serde::ser::Error for Error {
        fn custom<T: fmt::Display>(_: T) -> Self {
            Error::Invalid("invalid serialized number")
        }
    }
    macro_rules! scalar {
        ($($name:ident: $ty:ty),* $(,)?) => {$(fn $name(self, _: $ty) -> Result<()> { Ok(()) })*};
    }
    impl Serializer for Check {
        type Ok = ();
        type Error = Error;
        type SerializeSeq = Self;
        type SerializeTuple = Self;
        type SerializeTupleStruct = Self;
        type SerializeTupleVariant = Self;
        type SerializeMap = Self;
        type SerializeStruct = Self;
        type SerializeStructVariant = Self;
        scalar!(serialize_bool: bool, serialize_i8: i8, serialize_i16: i16,
            serialize_i32: i32, serialize_i64: i64, serialize_i128: i128,
            serialize_u8: u8, serialize_u16: u16, serialize_u32: u32,
            serialize_u64: u64, serialize_u128: u128, serialize_char: char,
            serialize_str: &str, serialize_bytes: &[u8]);
        fn serialize_f32(self, v: f32) -> Result<()> {
            if v.is_finite() {
                Ok(())
            } else {
                Err(Error::Invalid("nonfinite checkpoint number"))
            }
        }
        fn serialize_f64(self, v: f64) -> Result<()> {
            if v.is_finite() {
                Ok(())
            } else {
                Err(Error::Invalid("nonfinite checkpoint number"))
            }
        }
        fn serialize_none(self) -> Result<()> {
            Ok(())
        }
        fn serialize_some<T: serde::Serialize + ?Sized>(self, v: &T) -> Result<()> {
            v.serialize(self)
        }
        fn serialize_unit(self) -> Result<()> {
            Ok(())
        }
        fn serialize_unit_struct(self, _: &'static str) -> Result<()> {
            Ok(())
        }
        fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<()> {
            Ok(())
        }
        fn serialize_newtype_struct<T: serde::Serialize + ?Sized>(
            self,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(self)
        }
        fn serialize_newtype_variant<T: serde::Serialize + ?Sized>(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(self)
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self> {
            Ok(self)
        }
        fn serialize_tuple(self, _: usize) -> Result<Self> {
            Ok(self)
        }
        fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self> {
            Ok(self)
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self> {
            Ok(self)
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self> {
            Ok(self)
        }
        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self> {
            Ok(self)
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self> {
            Ok(self)
        }
    }
    macro_rules! sequence {
        ($trait:ident, $method:ident) => {
            impl $trait for Check {
                type Ok = ();
                type Error = Error;
                fn $method<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<()> {
                    v.serialize(*self)
                }
                fn end(self) -> Result<()> {
                    Ok(())
                }
            }
        };
    }
    sequence!(SerializeSeq, serialize_element);
    sequence!(SerializeTuple, serialize_element);
    sequence!(SerializeTupleStruct, serialize_field);
    sequence!(SerializeTupleVariant, serialize_field);
    impl SerializeMap for Check {
        type Ok = ();
        type Error = Error;
        fn serialize_key<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<()> {
            v.serialize(*self)
        }
        fn serialize_value<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<()> {
            v.serialize(*self)
        }
        fn end(self) -> Result<()> {
            Ok(())
        }
    }
    impl SerializeStruct for Check {
        type Ok = ();
        type Error = Error;
        fn serialize_field<T: serde::Serialize + ?Sized>(
            &mut self,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(*self)
        }
        fn end(self) -> Result<()> {
            Ok(())
        }
    }
    impl SerializeStructVariant for Check {
        type Ok = ();
        type Error = Error;
        fn serialize_field<T: serde::Serialize + ?Sized>(
            &mut self,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(*self)
        }
        fn end(self) -> Result<()> {
            Ok(())
        }
    }
}

/// Decode a fixed-cap collection without trusting its advertised allocation
/// size. Used by game checkpoint envelopes as well as session metadata.
pub fn bounded_vec<'de, D, T, const N: usize>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} values")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > N) {
                return Err(serde::de::Error::custom("collection bound"));
            }
            let mut values = Vec::new();
            while let Some(value) = seq.next_element()? {
                if values.len() == N {
                    return Err(serde::de::Error::custom("collection bound"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Visitor::<T, N>(std::marker::PhantomData))
}
