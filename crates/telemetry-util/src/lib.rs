//! Utilities to make working with tracing and telemetry easier.

/// Formats a [`std::time::Duration`] using the [`std::fmt::Display`].
///
/// # Example
///
/// ```
/// use tempo_telemetry_util::display_duration;
///
/// let timeout = std::time::Duration::from_millis(1500);
/// tracing::warn!(
///     timeout = %display_duration(timeout),
///     "computation did not finish in the prescribed time",
/// );
/// ```
pub fn display_duration(duration: std::time::Duration) -> DisplayDuration {
    DisplayDuration(duration)
}

pub struct DisplayDuration(std::time::Duration);
impl std::fmt::Display for DisplayDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use jiff::{
            SignedDuration,
            fmt::{
                StdFmtWrite,
                friendly::{Designator, SpanPrinter},
            },
        };
        static PRINTER: SpanPrinter = SpanPrinter::new().designator(Designator::Short);
        match SignedDuration::try_from(self.0) {
            Ok(duration) => PRINTER
                .print_duration(&duration, StdFmtWrite(f))
                .map_err(|_| std::fmt::Error),
            Err(_) => write!(f, "<duration greater than {:#}>", SignedDuration::MAX),
        }
    }
}

/// Emit an error as a tracing event with its full source chain intact.
///
/// This utility provides a streamlined way to emit errors as tracing event fields
/// and their full source-chain without verbose conversion to `&dyn std::error::Error`
/// trait objects.
///
/// # Why this exists
///
/// To emit errors as fields in tracing events in the way tracing intended (that is,
/// via `tracing::Value for dyn std::error::Error)`, one can either use
/// `error = &error as &dyn std::error::Error` for typed errors, or alternatively
/// `error = AsRef::<std::error::Error::as_ref(&error)` for dynamic errors such
/// `eyre::Report`. Both are verbose and not nice to use. Many users instead just reach
/// for the sigils `%` or `?`. But `%` uses the `Display` formatting for a type,
/// skipping its source chain. And `?` uses `Debug`, which can leak implementation details,
/// is hard to read, and can break formatting (in the case of eyre) -- and its inconsistent.
///
/// The [`error_field`] utility allows treating both errors the same way, while making
/// use of the tracing machinery.
///
/// # Notes on the implementation
///
/// [`tracing::Value`] is implemented for `E: dyn std::error::Error`, but
/// actually using it requires a verbose `error as &dyn std::error::Error`
/// for types that actually implement that trait. Or worse,
/// `AsRef::<dyn std::error::Error>::as_ref(&eyre_report)` for [`eyre::Report`],
/// which by itself does not implement the trait.
///
/// Right now the implementation requires an additional heap allocation of the
/// type-erased error object. Because usually errors are not handled in the hot
/// path of an application this should be an acceptable performance hit.
///
/// # Examples
///
/// ```
/// use eyre::WrapErr;
/// use tempo_telemetry_util::error_field;
/// let read_error: Result<(), std::io::Error> = Err(std::io::ErrorKind::NotFound.into());
/// if let Err(error) = Err::<(), _>(std::io::Error::from(std::io::ErrorKind::NotFound))
///     .wrap_err("failed opening config")
///     .wrap_err("failed to start server")
/// {
///     tracing::error!(
///         error = error_field(&error),
///     );
/// }
/// ```
/// This will print (using the standard `tracing_subscriber::fmt::init()` formatting subscriber):
/// ```text
/// 2025-08-08T14:38:17.541852Z ERROR tempo_telemetry_util: error=failed starting server error.sources=[failed opening config, entity not found]
/// ```
pub fn error_field<E, TMarker>(error: &E) -> Box<dyn tracing::Value + '_>
where
    E: AsTracingValue<TMarker>,
{
    error.as_tracing_value(private::Token)
}

#[doc(hidden)]
// NOTE: the marker is necessary to not run into impl conflicts due to the
// generic impl for E: std::error::Error. If eyre::Report ever implemented
// std::error::Error then impl AsTracingValue for E would no longer be unambiguous.
//
// This returns a boxed trait object because casting to borrowed (i.e. `&dyn Trait`)
// objects led to lifetime issues.
pub trait AsTracingValue<TMarker> {
    fn as_tracing_value(&self, _: private::Token) -> Box<dyn tracing::Value + '_>;
}

mod private {
    pub struct Token;
    pub struct Generic;
    pub struct Eyre;
}

impl<E: std::error::Error + 'static> AsTracingValue<private::Generic> for E {
    fn as_tracing_value(&self, _: private::Token) -> Box<dyn tracing::Value + '_> {
        Box::new(self as &(dyn std::error::Error + 'static))
    }
}

impl AsTracingValue<private::Eyre> for eyre::Report {
    fn as_tracing_value(&self, _: private::Token) -> Box<dyn tracing::Value + '_> {
        Box::new(AsRef::<dyn std::error::Error>::as_ref(self))
    }
}
