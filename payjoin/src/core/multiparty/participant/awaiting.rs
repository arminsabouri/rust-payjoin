use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

use super::ParticipantError;
use crate::hpke::{decrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::multiparty::persist::{
    ParticipantParametersAdoption, SessionParametersPollFailure, SessionParametersPollTransition,
};
use crate::multiparty::session::{MultipartySessionEvent, MultipartySessionOutcome};
use crate::multiparty::session_parameters::SessionParameters;
use crate::ohttp::{ohttp_encapsulate, process_get_res};
use crate::persist::MaybeFatalTransitionWithNoResults;
use crate::receive::v2::mailbox_endpoint;
use crate::uri::ShortId;
use crate::{IntoUrl, OhttpKeys, Request, Url};

/// Persistent context for a multiparty participant awaiting session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwaitingParticipantContext {
    mailbox_key: HpkeKeyPair,
    pub(crate) directory: Url,
    pub ohttp_keys: OhttpKeys,
    /// The other party's HPKE public key (initiator for responders, responder for initiators).
    pub(crate) reply_key: HpkePublicKey,
}

impl AwaitingParticipantContext {
    pub(crate) fn new(
        mailbox_key: HpkeKeyPair,
        directory: Url,
        ohttp_keys: OhttpKeys,
        reply_key: HpkePublicKey,
    ) -> Self {
        Self { mailbox_key, directory: directory.payjoin_directory_origin(), ohttp_keys, reply_key }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantAwaitingSessionParameters {
    /// HPKE public key for the Payjoin Directory mailbox that receives session parameters.
    pub(crate) parameters_mailbox_public_key: HpkePublicKey,
    pub(crate) context: AwaitingParticipantContext,
}

impl ParticipantAwaitingSessionParameters {
    /// Mailbox where the session creator POSTs parameters and this participant polls.
    pub(crate) fn parameters_mailbox_public_key(&self) -> &HpkePublicKey {
        &self.parameters_mailbox_public_key
    }

    fn parameters_mailbox_short_id(&self) -> ShortId {
        sha256::Hash::hash(&self.parameters_mailbox_public_key.to_compressed_bytes()).into()
    }

    fn session_parameters_poll_body(
        &self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        ParticipantError,
    > {
        let poll_target =
            mailbox_endpoint(&self.context.directory, &self.parameters_mailbox_short_id());
        ohttp_encapsulate(&self.context.ohttp_keys, "GET", poll_target.as_str(), None)
            .map_err(ParticipantError::OhttpEncapsulation)
    }

    /// Create an OHTTP encapsulated HTTP GET request to poll this participant's mailbox for
    /// HPKE-encrypted session parameters from the session creator.
    pub fn create_session_parameters_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), ParticipantError> {
        let (body, ohttp_ctx) = self.session_parameters_poll_body()?;
        let relay_url = crate::ohttp::full_relay_url(ohttp_relay, &self.context.directory)?;
        let req = Request::new_v2(&relay_url, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process the directory response after polling for session parameters.
    ///
    /// Returns no-results when the directory has nothing yet (HTTP 202 ACCEPTED).
    pub fn process_session_parameters_poll_response(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<SessionParametersPollTransition, SessionParametersPollFailure> {
        let current_state = self.clone();
        let session_parameters = match self.inner_process_session_parameters_poll_res(body, context)
        {
            Ok(session_parameters) => session_parameters,
            Err(e) => match &e {
                ParticipantError::DirectoryResponse(directory_error)
                    if !directory_error.is_fatal() =>
                {
                    return Err(SessionParametersPollFailure::Transient(e));
                }
                _ =>
                    return Err(SessionParametersPollFailure::Fatal(
                        MaybeFatalTransitionWithNoResults::fatal(
                            MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                            e,
                        ),
                    )),
            },
        };

        if let Some(session_parameters) = session_parameters {
            Ok(SessionParametersPollTransition::Adoption(
                ParticipantParametersAdoption::from_awaiting_participant(
                    &current_state,
                    session_parameters,
                ),
            ))
        } else {
            Ok(SessionParametersPollTransition::Stasis(current_state))
        }
    }

    fn inner_process_session_parameters_poll_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<SessionParameters>, ParticipantError> {
        let body =
            match process_get_res(body, context).map_err(ParticipantError::DirectoryResponse)? {
                Some(body) => body,
                None => return Ok(None),
            };

        let (params_bytes, _creator_pubkey) =
            decrypt_message_a(&body, self.context.mailbox_key.secret_key())
                .map_err(ParticipantError::Hpke)?;
        let session_parameters = SessionParameters::from_message_a_body(&params_bytes)
            .map_err(ParticipantError::SessionParameters)?;
        Ok(Some(session_parameters))
    }
}
