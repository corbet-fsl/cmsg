//! Preserve duplicate-field refusal before the owner's Value-based client.
use super::*;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserializer as _,
};
use serde_json::value::RawValue;
use std::fmt;

// serde_json's arbitrary-precision numbers arrive through deserialize_any as
// private map-shaped values. Inspect real JSON containers explicitly instead:
// object keys remain object keys, while maintained serde_json parses primitives.
// Borrow raw child spans so nested input does not allocate a copy at each level.
struct Container {
    depth: usize,
}
impl<'de> Visitor<'de> for Container {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object fields")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(raw) = sequence.next_element::<&'de RawValue>()? {
            values.push(parse(raw, self.depth).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "de::Error::custom invalid JSON value",
                    de::Error::custom("invalid JSON value"),
                    &__cause,
                )
            })?);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if values.contains_key(&name) {
                return Err(de::Error::custom("duplicate field"));
            }
            let raw = map.next_value::<&'de RawValue>()?;
            let value = parse(raw, self.depth).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "de::Error::custom invalid JSON value",
                    de::Error::custom("invalid JSON value"),
                    &__cause,
                )
            })?;
            values.insert(name, value);
        }
        Ok(Value::Object(values))
    }
}
fn parse(raw: &RawValue, depth: usize) -> Result<Value> {
    // Each borrowed container has its own serde deserializer. Preserve the
    // original bounded nesting policy rather than resetting it per child.
    if depth >= 128 {
        return Err(ErrorCode::InvalidRequest);
    }
    let bytes = raw.get().trim_start();
    let mut decoder = serde_json::Deserializer::from_str(bytes);
    let value = match bytes.as_bytes().first() {
        Some(b'{') => decoder.deserialize_map(Container { depth: depth + 1 }),
        Some(b'[') => decoder.deserialize_seq(Container { depth: depth + 1 }),
        _ => Value::deserialize(&mut decoder),
    }
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    decoder.end().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    if let Value::Number(number) = &value {
        if number.as_f64().is_none_or(|number| !number.is_finite()) {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(value)
}

pub(super) fn unique_value(raw: &str) -> Result<Value> {
    let raw: &RawValue = serde_json::from_str(raw).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    parse(raw, 0)
}
