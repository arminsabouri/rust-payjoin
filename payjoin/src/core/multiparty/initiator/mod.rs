mod error;
mod session;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
pub use error::{InitiatorError, InitiatorSessionError};
use serde::{Deserialize, Serialize};
pub use session::{
    replay_event_log, InitiatorEvent, InitiatorHistory, InitiatorOutcome, InitiatorSession,
    InitiatorStatus,
};
#[cfg(target_arch = "wasm32")]
use web_time::Duration;

use crate::hpke::{decrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::multiparty::uri::{build_multiparty_pj_uri, MultipartyPjUri};
use crate::ohttp::{ohttp_encapsulate, process_get_res};
use crate::persist::{MaybeFatalTransitionWithNoResults, NextStateTransition};
use crate::receive::v2::mailbox_endpoint;
use crate::uri::{PjParam, ShortId};
use crate::{IntoUrl, OhttpKeys, Request, Url};

/// Persistent context for a multiparty initiator session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitiatorContext {
    initiator_key: HpkeKeyPair,
    directory: Url,
    ohttp_keys: OhttpKeys,
    reply_key: Option<HpkePublicKey>,
}

impl InitiatorContext {
    fn initiator_mailbox_id(&self) -> ShortId {
        sha256::Hash::hash(&self.initiator_key.public_key().to_compressed_bytes()).into()
    }

    fn full_relay_url(&self, ohttp_relay: impl IntoUrl) -> Result<Url, InitiatorError> {
        let relay_base = ohttp_relay.into_url()?;

        let directory_base =
            self.directory.join("/").map_err(|e| InitiatorError::ParseUrl(e.into()))?;

        relay_base
            .join(&format!("/{directory_base}"))
            .map_err(|e| InitiatorError::ParseUrl(e.into()))
    }
}

/// Multiparty initiator state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initiator<State> {
    pub(crate) state: State,
    pub(crate) context: InitiatorContext,
}

pub struct InitiatorBuilder(InitiatorContext);

impl InitiatorBuilder {
    pub fn new(
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
    ) -> Result<Self, crate::into_url::Error> {
        let initiator_key = HpkeKeyPair::gen_keypair();
        Ok(Self(InitiatorContext {
            initiator_key,
            directory: directory.into_url()?,
            ohttp_keys,
            reply_key: None,
        }))
    }

    pub fn build(self) -> NextStateTransition<InitiatorEvent, Initiator<Initialized>> {
        NextStateTransition::success(
            InitiatorEvent::Created(self.0.clone()),
            Initiator { state: Initialized {}, context: self.0 },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {}

fn initiator_pj_param(context: &InitiatorContext) -> PjParam {
    // v2 `pj` endpoints require an EX fragment; session expiration is not modeled yet.
    let expiration = crate::time::Time::from_now(Duration::from_secs(60 * 60 * 24))
        .expect("placeholder expiration should be representable");
    PjParam::V2(crate::uri::v2::PjParam::new(
        context.directory.clone(),
        context.initiator_mailbox_id(),
        expiration,
        context.ohttp_keys.clone(),
        context.initiator_key.public_key().clone(),
    ))
}

/// Build a BIP-321 Payjoin URI for responders (`pj` + `mppj=1`, no address).
pub(crate) fn pj_uri(context: &InitiatorContext) -> MultipartyPjUri {
    build_multiparty_pj_uri(&initiator_pj_param(context))
}

impl Initiator<Initialized> {
    /// BIP-321 Payjoin URI shared with responders (`pj` + `mppj=1`, no address).
    pub fn pj_uri(&self) -> MultipartyPjUri { pj_uri(&self.context) }

    fn poll_req_body(
        &self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        InitiatorError,
    > {
        let poll_target =
            mailbox_endpoint(&self.context.directory, &self.context.initiator_mailbox_id());
        ohttp_encapsulate(&self.context.ohttp_keys, "GET", poll_target.as_str(), None)
            .map_err(InitiatorError::OhttpEncapsulation)
    }

    /// Create an OHTTP encapsulated HTTP GET request to poll the initiator mailbox.
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), InitiatorError> {
        let (body, ohttp_ctx) = self.poll_req_body()?;
        let relay_url = self.context.full_relay_url(ohttp_relay)?;
        let req = Request::new_v2(&relay_url, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process the response to a poll request from the Payjoin Directory.
    ///
    /// On success, transitions after decrypting and parsing only the sender's reply key from
    /// message A. Returns no-results when the directory has nothing yet (HTTP 202 ACCEPTED).
    pub fn process_poll_request(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        InitiatorEvent,
        Initiator<HasReplyKey>,
        Initiator<Initialized>,
        InitiatorSessionError,
    > {
        // TODO: this should transition to a common state where responder and initator are waiting
        let current_state = self.clone();
        let reply_key = match self.inner_process_poll_res(body, context) {
            Ok(reply_key) => reply_key,
            Err(e) => match &e {
                InitiatorError::DirectoryResponse(directory_error)
                    if !directory_error.is_fatal() =>
                {
                    return MaybeFatalTransitionWithNoResults::transient(e);
                }
                _ =>
                    return MaybeFatalTransitionWithNoResults::fatal(
                        InitiatorEvent::Closed(InitiatorOutcome::Failure),
                        e,
                    ),
            },
        };

        if let Some(reply_key) = reply_key {
            MaybeFatalTransitionWithNoResults::success(
                InitiatorEvent::RetrievedReplyKey(reply_key.clone()),
                Initiator {
                    state: HasReplyKey {},
                    context: InitiatorContext {
                        reply_key: Some(reply_key),
                        ..current_state.context
                    },
                },
            )
        } else {
            MaybeFatalTransitionWithNoResults::no_results(current_state)
        }
    }

    fn inner_process_poll_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<HpkePublicKey>, InitiatorError> {
        let body =
            match process_get_res(body, context).map_err(InitiatorError::DirectoryResponse)? {
                Some(body) => body,
                None => return Ok(None),
            };

        let (_, reply_key) = decrypt_message_a(&body, self.context.initiator_key.secret_key())
            .map_err(InitiatorError::Hpke)?;

        Ok(Some(reply_key))
    }

    pub(crate) fn apply_retrieved_reply_key(self, reply_key: HpkePublicKey) -> InitiatorSession {
        InitiatorSession::HasReplyKey(Initiator {
            state: HasReplyKey {},
            context: InitiatorContext { reply_key: Some(reply_key), ..self.context },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasReplyKey {}
impl Initiator<HasReplyKey> {}
