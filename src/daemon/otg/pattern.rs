//! OTG "Pattern" semantics for packet header fields: a field can be a
//! fixed value, an explicit list, or a bounded counter/random walk over
//! a fixed-width integer. Every choice is materialized once into a
//! finite, cyclic sequence of concrete values ([`Resolved`]) so the hot
//! Tx path only ever indexes a precomputed array.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail, ensure};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

use crate::proto::ether::MacAddr;

/// A fixed-width field value that can be stepped and randomized modulo
/// its own bit width (48 for MAC, 32 for IPv4, 128 for IPv6, ...).
pub trait PatternStep: Copy {
    const BITS: u32;
    fn to_u128(self) -> u128;
    fn from_u128(v: u128) -> Self;
}

fn mask(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

impl PatternStep for MacAddr {
    const BITS: u32 = 48;

    fn to_u128(self) -> u128 {
        let mut buf = [0u8; 16];
        buf[10..16].copy_from_slice(&self.octets());
        u128::from_be_bytes(buf)
    }

    fn from_u128(v: u128) -> Self {
        let bytes = v.to_be_bytes();
        MacAddr::new(bytes[10..16].try_into().unwrap())
    }
}

impl PatternStep for Ipv4Addr {
    const BITS: u32 = 32;

    fn to_u128(self) -> u128 {
        u32::from(self) as u128
    }

    fn from_u128(v: u128) -> Self {
        Ipv4Addr::from((v & mask(Self::BITS)) as u32)
    }
}

impl PatternStep for Ipv6Addr {
    const BITS: u32 = 128;

    fn to_u128(self) -> u128 {
        u128::from(self)
    }

    fn from_u128(v: u128) -> Self {
        Ipv6Addr::from(v)
    }
}

impl PatternStep for u8 {
    const BITS: u32 = 8;

    fn to_u128(self) -> u128 {
        self as u128
    }

    fn from_u128(v: u128) -> Self {
        (v & mask(Self::BITS)) as u8
    }
}

impl PatternStep for u16 {
    const BITS: u32 = 16;

    fn to_u128(self) -> u128 {
        self as u128
    }

    fn from_u128(v: u128) -> Self {
        (v & mask(Self::BITS)) as u16
    }
}

/// One OTG `Pattern.*` choice for a header field of type `T`. `auto` is
/// intentionally absent: it only makes sense for `Flow.Router` (device)
/// endpoints, which pktflow does not support (flows only use
/// `Flow.Port` endpoints).
#[derive(Debug, Clone)]
pub enum Pattern<T> {
    Value(T),
    Values(Vec<T>),
    Increment {
        start: T,
        step: T,
        count: u32,
    },
    Decrement {
        start: T,
        step: T,
        count: u32,
    },
    Random {
        min: T,
        max: T,
        seed: u32,
        count: u32,
    },
}

/// A materialized, finite cycle of values for one header field.
#[derive(Debug, Clone)]
pub struct Resolved<T> {
    values: Vec<T>,
}

impl<T: Copy> Resolved<T> {
    /// Length of the repeating cycle.
    pub fn period(&self) -> usize {
        self.values.len()
    }

    /// The value at cycle position `i`, wrapping around `period()`.
    pub fn at(&self, i: usize) -> T {
        self.values[i % self.values.len()]
    }
}

impl<T: PatternStep> Pattern<T> {
    pub fn resolve(&self) -> Result<Resolved<T>> {
        let values = match self {
            Pattern::Value(v) => vec![*v],
            Pattern::Values(vs) => {
                ensure!(!vs.is_empty(), "pattern \"values\" must not be empty");
                vs.clone()
            }
            Pattern::Increment { start, step, count } => {
                ensure!(*count >= 1, "pattern increment count must be at least 1");
                let m = mask(T::BITS);
                let base = start.to_u128() & m;
                let delta = step.to_u128() & m;
                (0..*count)
                    .map(|i| T::from_u128(base.wrapping_add(delta.wrapping_mul(i as u128)) & m))
                    .collect()
            }
            Pattern::Decrement { start, step, count } => {
                ensure!(*count >= 1, "pattern decrement count must be at least 1");
                let m = mask(T::BITS);
                let base = start.to_u128() & m;
                let delta = step.to_u128() & m;
                (0..*count)
                    .map(|i| T::from_u128(base.wrapping_sub(delta.wrapping_mul(i as u128)) & m))
                    .collect()
            }
            Pattern::Random {
                min,
                max,
                seed,
                count,
            } => {
                ensure!(*count >= 1, "pattern random count must be at least 1");
                let lo = min.to_u128();
                let hi = max.to_u128();
                ensure!(lo <= hi, "pattern random \"min\" must not exceed \"max\"");
                // A seed of 0 asks for a non-deterministic sequence; any
                // other value must reproduce the same sequence every time.
                if *seed == 0 {
                    let mut rng = rand::rng();
                    (0..*count)
                        .map(|_| T::from_u128(rng.random_range(lo..=hi)))
                        .collect()
                } else {
                    let mut rng = StdRng::seed_from_u64(*seed as u64);
                    (0..*count)
                        .map(|_| T::from_u128(rng.random_range(lo..=hi)))
                        .collect()
                }
            }
        };
        Ok(Resolved { values })
    }
}

/// Wire representation of an OTG `Pattern.*` object: a `choice` tag plus
/// one optional field per choice, exactly mirroring the JSON shape.
/// `S` is the wire scalar type (`String` for mac/ipv4/ipv6, `u8`/`u16`
/// for plain integer fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPattern<S> {
    #[serde(default = "default_choice_value")]
    pub choice: String,
    pub value: Option<S>,
    pub values: Option<Vec<S>>,
    pub increment: Option<RawCounter<S>>,
    pub decrement: Option<RawCounter<S>>,
    pub random: Option<RawRandom<S>>,
}

fn default_choice_value() -> String {
    "value".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCounter<S> {
    pub start: S,
    pub step: S,
    #[serde(default = "one_u32")]
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawRandom<S> {
    pub min: S,
    pub max: S,
    #[serde(default)]
    pub seed: u32,
    #[serde(default = "one_u32")]
    pub count: u32,
}

fn one_u32() -> u32 {
    1
}

/// Converts a wire-shaped [`RawPattern`] into a [`Pattern`], applying
/// `convert` to every scalar (parses a MAC/IPv4/IPv6 string, or is the
/// identity for fields whose wire type already is `T`). `allow_random`
/// is `false` for MAC fields, which the OTG spec does not define a
/// `random` choice for.
pub fn from_raw<S, T>(
    raw: RawPattern<S>,
    convert: impl Fn(S) -> Result<T>,
    allow_random: bool,
) -> Result<Pattern<T>>
where
    T: PatternStep,
{
    Ok(match raw.choice.as_str() {
        "value" => Pattern::Value(convert(
            raw.value
                .context("pattern choice \"value\" requires a \"value\" field")?,
        )?),
        "values" => {
            let values = raw
                .values
                .context("pattern choice \"values\" requires a \"values\" field")?;
            ensure!(!values.is_empty(), "pattern \"values\" must not be empty");
            Pattern::Values(
                values
                    .into_iter()
                    .map(convert)
                    .collect::<Result<Vec<_>>>()?,
            )
        }
        "increment" => {
            let c = raw
                .increment
                .context("pattern choice \"increment\" requires an \"increment\" field")?;
            Pattern::Increment {
                start: convert(c.start)?,
                step: convert(c.step)?,
                count: c.count,
            }
        }
        "decrement" => {
            let c = raw
                .decrement
                .context("pattern choice \"decrement\" requires a \"decrement\" field")?;
            Pattern::Decrement {
                start: convert(c.start)?,
                step: convert(c.step)?,
                count: c.count,
            }
        }
        "random" => {
            ensure!(
                allow_random,
                "pattern choice \"random\" is not supported for this field"
            );
            let r = raw
                .random
                .context("pattern choice \"random\" requires a \"random\" field")?;
            Pattern::Random {
                min: convert(r.min)?,
                max: convert(r.max)?,
                seed: r.seed,
                count: r.count,
            }
        }
        "auto" => bail!(
            "pattern choice \"auto\" is not supported (flows only use Flow.Port endpoints, not Flow.Router devices)"
        ),
        other => bail!("unsupported pattern choice {other:?}"),
    })
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Least common multiple of two positive periods; `None` on overflow.
pub fn lcm(a: u64, b: u64) -> Option<u64> {
    (a / gcd(a, b)).checked_mul(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_pattern_has_period_one() {
        let p = Pattern::Value(7u16).resolve().unwrap();
        assert_eq!(p.period(), 1);
        assert_eq!(p.at(0), 7);
        assert_eq!(p.at(5), 7);
    }

    #[test]
    fn values_pattern_cycles_through_the_list() {
        let p = Pattern::Values(vec![1u8, 2, 3]).resolve().unwrap();
        assert_eq!(p.period(), 3);
        assert_eq!((0..5).map(|i| p.at(i)).collect::<Vec<_>>(), [1, 2, 3, 1, 2]);
    }

    #[test]
    fn increment_wraps_at_the_field_width() {
        let p = Pattern::Increment {
            start: 254u8,
            step: 1,
            count: 4,
        }
        .resolve()
        .unwrap();
        assert_eq!(
            (0..4).map(|i| p.at(i)).collect::<Vec<_>>(),
            [254, 255, 0, 1]
        );
    }

    #[test]
    fn decrement_wraps_at_the_field_width() {
        let p = Pattern::Decrement {
            start: 1u8,
            step: 1,
            count: 3,
        }
        .resolve()
        .unwrap();
        assert_eq!((0..3).map(|i| p.at(i)).collect::<Vec<_>>(), [1, 0, 255]);
    }

    #[test]
    fn increment_on_ipv4_matches_dotted_decimal_expectation() {
        let p = Pattern::Increment {
            start: Ipv4Addr::new(10, 0, 0, 1),
            step: Ipv4Addr::new(0, 0, 0, 1),
            count: 3,
        }
        .resolve()
        .unwrap();
        assert_eq!(p.at(0), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(p.at(1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(p.at(2), Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn random_is_deterministic_for_a_nonzero_seed() {
        let pattern = Pattern::Random {
            min: 0u16,
            max: 1000,
            seed: 42,
            count: 5,
        };
        let a = pattern.resolve().unwrap();
        let b = pattern.resolve().unwrap();
        assert_eq!(
            (0..5).map(|i| a.at(i)).collect::<Vec<_>>(),
            (0..5).map(|i| b.at(i)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn random_rejects_min_greater_than_max() {
        let err = Pattern::Random {
            min: 10u8,
            max: 5,
            seed: 1,
            count: 1,
        }
        .resolve()
        .unwrap_err();
        assert!(err.to_string().contains("min"));
    }

    #[test]
    fn lcm_combines_independent_periods() {
        assert_eq!(lcm(4, 3), Some(12));
        assert_eq!(lcm(1, 5), Some(5));
        assert_eq!(lcm(6, 4), Some(12));
    }
}
