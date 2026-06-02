#[cfg_attr(docsrs, doc(cfg(feature = "multiparty")))]
pub mod linked_mailbox;
#[cfg_attr(docsrs, doc(cfg(feature = "multiparty")))]
pub mod uri;
pub use uri::{build_multiparty_pj_uri, MultipartyPjUri, MultipartyUriError};
