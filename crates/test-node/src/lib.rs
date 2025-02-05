#![feature(let_chains)]

pub mod provider;

pub use provider::keystore;

/// Configure Insta snapshot name.
///
/// # Example
///
/// ```rust,ignore
/// snapshot!("issuer:immediate");
///
/// ...
///
/// assert_snapshot!("credential", vc, {
///    ".validFrom" => "[validFrom]",
///    ".credentialSubject" => insta::sorted_redaction()
/// });
/// ```
///
/// will result in a snapshot named `credential@issuer:immediate.snap`.
#[macro_export]
macro_rules! snapshot{
    ($($expr:expr),*) => {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_suffix(format!($($expr,)*));
        settings.set_prepend_module_to_snapshot(false);
        let _guard = settings.bind_to_scope();
    }
}
