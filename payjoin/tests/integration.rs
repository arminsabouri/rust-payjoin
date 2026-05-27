mod integration {
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use bitcoin::bech32::NoChecksum;
    use bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE;
    use bitcoin::psbt::{Input as PsbtInput, Psbt};
    use bitcoin::{Amount, FeeRate, OutPoint, TxIn, TxOut, Weight};
    use payjoin::receive::v1::build_v1_pj_uri;
    use payjoin::receive::InputPair;
    use payjoin::{ImplementationError, OutputSubstitution, PjUri, Request, Uri, Url};
    use payjoin_test_utils::corepc_node::vtype::ListUnspentItem;
    use payjoin_test_utils::corepc_node::AddressType;
    use payjoin_test_utils::{corepc_node, init_bitcoind_sender_receiver, init_tracing, BoxError};
    use serde_json::json;

    const EXAMPLE_URL: &str = "https://example.com";
    /// Transaction weight components for fee calculation
    /// Useful resource: https://bitcoin.stackexchange.com/a/84006
    const TX_HEADER_LEGACY_WEIGHT: u64 = 40;
    const TX_HEADER_WEIGHT: u64 = 42;
    const P2PKH_INPUT_WEIGHT: u64 = 592;
    const NESTED_P2WPKH_INPUT_WEIGHT: u64 = 364;
    const P2WPKH_INPUT_WEIGHT: u64 = 272;
    const P2TR_INPUT_WEIGHT: u64 = 230;
    const P2WPKH_OUTPUT_WEIGHT: u64 = 124;

    #[cfg(feature = "v1")]
    mod v1 {
        use payjoin::send::v1::SenderBuilder;
        use payjoin::UriExt;
        use tracing::debug;

        use super::*;

        #[test]
        fn v1_to_v1_p2pkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Legacy),
                Some(AddressType::Legacy),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_LEGACY_WEIGHT + (P2PKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            )
            // bitcoin-cli wallet uses signature grinding to save one vbyte on the original PSBT.
            // subtract it here
            - Weight::from_vb_unchecked(1);
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        #[test]
        fn v1_to_v1_nested_p2wpkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::P2shSegwit),
                Some(AddressType::P2shSegwit),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (NESTED_P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        #[test]
        fn v1_to_v1_p2wpkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32),
                Some(AddressType::Bech32),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        #[test]
        fn v1_to_v1_taproot() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32m),
                Some(AddressType::Bech32m),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT
                    + (P2TR_INPUT_WEIGHT * 2)
                    + (P2WPKH_OUTPUT_WEIGHT * 2),
            )
            // bitcoin-cli wallet overestimates taproot inputs in the original PSBT by one vbyte:
            // https://github.com/payjoin/rust-payjoin/issues/369#issuecomment-2657539591
            // add it here
            + Weight::from_vb_unchecked(1);
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        fn do_v1_to_v1(
            sender: corepc_node::Client,
            receiver: corepc_node::Client,
            expected_weight: Weight,
        ) -> Result<(), BoxError> {
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {psbt:#?}");
            let (req, ctx) = SenderBuilder::new(psbt, uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_v1_pj_request(req, headers, &receiver, None, None, None)?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            assert_eq!(payjoin_tx.input.len(), 2);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(51.0)?
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - network_fees
            );
            Ok(())
        }

        #[test]
        fn allow_mixed_input_scripts() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32),
                Some(AddressType::P2shSegwit),
            )?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {psbt:#?}");
            let (req, _ctx) = SenderBuilder::new(psbt, uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // This should NOT error because the receiver is attempting to introduce mixed input script types
            assert!(handle_v1_pj_request(req, headers, &receiver, None, None, None).is_ok());
            Ok(())
        }
    }

    // not all needs v1
    #[cfg(all(feature = "io", feature = "v2", feature = "v1", feature = "_manual-tls"))]
    mod v2 {
        // use std::random;
        use std::sync::Arc;
        use std::time::Duration;

        use bitcoin::hashes::{sha256, Hash, HashEngine};
        use bitcoin::{secp256k1, Address, Transaction};
        use hpke::rand_core::OsRng;
        use http::StatusCode;
        use payjoin::persist::OptionalTransitionOutcome;
        use payjoin::receive::v2::{
            replay_event_log as replay_receiver_event_log, Monitor, PayjoinProposal,
            ReceiveSession, Receiver, ReceiverBuilder, SessionStatus, UncheckedOriginalPayload,
        };
        use payjoin::send::v2::{replay_event_log as replay_sender_event_log, SenderBuilder};
        use payjoin::send::ResponseError;
        use payjoin::{OhttpKeys, PjUri, UriExt};
        use payjoin_test_utils::{
            BoxSendSyncError, InMemoryPersister, SessionPersister, TestServices,
        };
        use reqwest::{Client, Response};

        use super::*;

        /// Possible actions the sender can take after receiving the Payjoin proposal from the
        /// receiver.
        ///
        /// NOTE: This list is not finalized, as how the receiver can monitor non-segwit
        /// sender addresses are still pending implementation: https://github.com/payjoin/rust-payjoin/issues/1214
        enum SenderFinalAction {
            SignAndBroadcastPayjoinProposal,
            BroadcastFallbackTransaction,
        }

        // Generate a short id based on shared secret and index
        fn generate_short_id(shared_secret: &[u8], index: u64) -> payjoin::directory::ShortId {
            let mut engine = sha256::Hash::engine();
            engine.input(b"v0-PayjoinDirectoryEntry");
            engine.input(shared_secret);
            engine.input(index.to_le_bytes().as_slice());
            sha256::Hash::from_engine(engine).into()
        }

        // Padding sized to match payjoin/src/core/ohttp.rs:
        // ENCAPSULATED_MESSAGE_BYTES - (N_ENC=65 + N_T=16 + OHTTP_REQ_HEADER_BYTES=7)
        const PADDED_BHTTP_REQ_BYTES: usize =
            payjoin::directory::ENCAPSULATED_MESSAGE_BYTES - (65 + 16 + 7);

        fn encapsulate_request(
            ohttp_keys: &payjoin::OhttpKeys,
            method: &str,
            target_url: &str,
            body: Option<&[u8]>,
        ) -> Result<(Vec<u8>, ohttp::ClientResponse), BoxSendSyncError> {
            let mut config = ohttp_keys.0.clone();
            let ctx = ohttp::ClientRequest::from_config(&mut config)?;
            let url = payjoin::Url::parse(target_url)?;
            let authority = match url.port() {
                Some(p) => format!("{}:{}", url.host_str(), p),
                None => url.host_str(),
            };
            let mut bhttp_msg = bhttp::Message::request(
                method.as_bytes().to_vec(),
                url.scheme().as_bytes().to_vec(),
                authority.into_bytes(),
                url.path().as_bytes().to_vec(),
            );
            if let Some(b) = body {
                bhttp_msg.write_content(b);
            }
            let mut bhttp_buf = vec![0u8; PADDED_BHTTP_REQ_BYTES];
            bhttp_msg.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_buf.as_mut_slice())?;
            let (encapsulated, ohttp_ctx) = ctx.encapsulate(&bhttp_buf)?;
            Ok((encapsulated, ohttp_ctx))
        }

        fn decapsulate_response(
            ohttp_ctx: ohttp::ClientResponse,
            encapsulated: &[u8],
        ) -> Result<(http::StatusCode, Vec<u8>), BoxSendSyncError> {
            let bhttp_bytes = ohttp_ctx.decapsulate(encapsulated)?;
            let mut cursor = std::io::Cursor::new(bhttp_bytes);
            let msg = bhttp::Message::read_bhttp(&mut cursor)?;
            let code = msg.control().status().ok_or("missing status")?.code();
            let status = http::StatusCode::from_u16(code)?;
            Ok((status, msg.content().to_vec()))
        }

        // The relay extracts the gateway URI from its request path; embed the
        // directory URL there (matches `SessionContext::full_relay_url`).
        fn relay_url_for_directory(services: &TestServices) -> String {
            format!("{}/{}", services.ohttp_relay_url(), services.directory_url())
        }

        async fn write_mailbox(
            services: &TestServices,
            ohttp_keys: &payjoin::OhttpKeys,
            short_id: payjoin::directory::ShortId,
            message: &[u8],
        ) -> Result<http::StatusCode, BoxSendSyncError> {
            let target = format!("{}/{}", services.directory_url(), short_id);
            let (req, ohttp_ctx) = encapsulate_request(ohttp_keys, "POST", &target, Some(message))?;
            let response = services
                .http_agent()
                .post(relay_url_for_directory(services))
                .header("Content-Type", "message/ohttp-req")
                .body(req)
                .send()
                .await?;
            assert!(response.status().is_success(), "relay status: {}", response.status());
            let body = response.bytes().await?;
            let (status, _) = decapsulate_response(ohttp_ctx, &body)?;
            Ok(status)
        }

        async fn read_mailbox(
            services: &TestServices,
            ohttp_keys: &payjoin::OhttpKeys,
            short_id: payjoin::directory::ShortId,
        ) -> Result<Option<Vec<u8>>, BoxSendSyncError> {
            let target = format!("{}/{}", services.directory_url(), short_id);
            let (req, ohttp_ctx) = encapsulate_request(ohttp_keys, "GET", &target, None)?;
            let response = services
                .http_agent()
                .post(relay_url_for_directory(services))
                .header("Content-Type", "message/ohttp-req")
                .body(req)
                .send()
                .await?;
            assert!(response.status().is_success(), "relay status: {}", response.status());
            let body = response.bytes().await?;
            let (status, content) = decapsulate_response(ohttp_ctx, &body)?;
            match status {
                http::StatusCode::OK => Ok(Some(content)),
                http::StatusCode::ACCEPTED => Ok(None),
                other => Err(format!("unexpected get_mailbox status: {}", other).into()),
            }
        }

        /// Append-only broadcast channel shared by multiple participants.
        ///
        /// Each participant is initialized with the same shared identity.
        trait CollaborativeMessageSet {
            type Message;
            type Error;

            type Messages<'a>: futures::Stream<Item = Result<Self::Message, Self::Error>>
                + Send
                + 'a
            where
                Self: 'a;

            /// Append one complete message.
            async fn write(&self, message: Self::Message) -> Result<(), Self::Error>;

            /// Read all messages from the beginning in server-determined order.
            fn read(&self) -> Self::Messages<'_>;
        }

        /// `CollaborativeMessageSet` over a chain of directory mailboxes.
        ///
        /// `short_id(i) = H(shared_secret, i)`. `write` walks forward on 409
        /// so concurrent writers converge on distinct slots without
        /// coordinating an index out-of-band. `read` polls each slot in
        /// order and stops when the directory's local wait timeout elapses
        /// without a payload.
        struct DirectoryLinkedMailbox<'a> {
            services: &'a TestServices,
            ohttp_keys: &'a payjoin::OhttpKeys,
            shared_secret: [u8; 32],
            // Local-only hint for this peer; it starts at 0 and never
            // decreases. Different peers do not share this hint, so each
            // peer races forward independently and relies on the directory's
            // 409 to resolve concurrent collisions.
            next_write_index: std::sync::atomic::AtomicU64,
        }

        impl<'a> DirectoryLinkedMailbox<'a> {
            fn new(
                services: &'a TestServices,
                ohttp_keys: &'a payjoin::OhttpKeys,
                shared_secret: [u8; 32],
            ) -> Self {
                Self {
                    services,
                    ohttp_keys,
                    shared_secret,
                    next_write_index: std::sync::atomic::AtomicU64::new(0),
                }
            }
        }

        impl<'a> CollaborativeMessageSet for DirectoryLinkedMailbox<'a> {
            type Message = Vec<u8>;
            type Error = BoxSendSyncError;
            type Messages<'b>
                = std::pin::Pin<
                Box<dyn futures::Stream<Item = Result<Vec<u8>, BoxSendSyncError>> + Send + 'b>,
            >
            where
                Self: 'b;

            async fn write(&self, message: Vec<u8>) -> Result<(), Self::Error> {
                use std::sync::atomic::Ordering;
                let mut i = self.next_write_index.load(Ordering::Relaxed);
                loop {
                    let short_id = generate_short_id(&self.shared_secret, i);
                    let status =
                        write_mailbox(self.services, self.ohttp_keys, short_id, &message).await?;
                    match status {
                        http::StatusCode::OK => {
                            // Advance the local hint past the slot we just claimed.
                            self.next_write_index.fetch_max(i + 1, Ordering::Relaxed);
                            return Ok(());
                        }
                        http::StatusCode::CONFLICT => {
                            i += 1;
                        }
                        other =>
                            return Err(format!("unexpected post_mailbox status: {}", other).into()),
                    }
                }
            }

            fn read(&self) -> Self::Messages<'_> {
                let secret = self.shared_secret;
                let services = self.services;
                let keys = self.ohttp_keys;
                Box::pin(async_stream::stream! {
                    let mut i = 0u64;
                    loop {
                        let short_id = generate_short_id(&secret, i);
                        match read_mailbox(services, keys, short_id).await {
                            Ok(Some(payload)) => {
                                yield Ok(payload);
                                i += 1;
                            }
                            // Local timeout: no payload at this slot. Could be true end-of-log.
                            Ok(None) => break,
                            Err(e) => {
                                yield Err(e);
                                break;
                            }
                        }
                    }
                })
            }
        }

        async fn do_linked_mailbox_test(services: &TestServices) -> Result<(), BoxSendSyncError> {
            use futures::StreamExt;

            services.wait_for_services_ready().await?;
            let ohttp_keys = services.fetch_ohttp_keys().await?;
            let shared_secret = secp256k1::SecretKey::new(&mut OsRng).secret_bytes();

            // Each peer is independently initialized with only the shared secret.
            let alice = DirectoryLinkedMailbox::new(services, &ohttp_keys, shared_secret);
            let bob = DirectoryLinkedMailbox::new(services, &ohttp_keys, shared_secret);
            let carol = DirectoryLinkedMailbox::new(services, &ohttp_keys, shared_secret);

            let alice_msg = b"Hello from Alice".to_vec();
            let bob_msg = b"Hello from Bob".to_vec();
            let carol_msg = b"Hello from Carol".to_vec();

            let (ra, rb, rc) = tokio::join!(
                alice.write(alice_msg.clone()),
                bob.write(bob_msg.clone()),
                carol.write(carol_msg.clone()),
            );
            ra?;
            rb?;
            rc?;

            // Any peer (with the same secret) can iterate the full message
            // set. Server-side ordering is opaque, so compare as a set.
            let stream = alice.read();
            tokio::pin!(stream);
            let mut observed = Vec::new();
            while let Some(item) = stream.next().await {
                observed.push(item?);
            }
            assert_eq!(observed.len(), 3, "reader should see all three appended messages");

            use std::collections::HashSet;
            let expected: HashSet<Vec<u8>> = [alice_msg, bob_msg, carol_msg].into_iter().collect();
            let observed_set: HashSet<Vec<u8>> = observed.into_iter().collect();
            assert_eq!(observed_set, expected);

            // A peer initialized with a different secret sees an empty message set.
            let other_secret = secp256k1::SecretKey::new(&mut OsRng).secret_bytes();
            let stranger = DirectoryLinkedMailbox::new(services, &ohttp_keys, other_secret);
            let stranger_stream = stranger.read();
            tokio::pin!(stranger_stream);
            assert!(stranger_stream.next().await.is_none(), "unrelated message set must be empty");

            Ok(())
        }

        #[tokio::test]
        async fn test_create_linked_mailbox() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            // Three peers each hold an independent CollaborativeMessageSet
            // handle initialized only with the shared secret.
            let result = tokio::select!(
                err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
                err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
                res = do_linked_mailbox_test(&services) => res
            );
            result
        }

        #[tokio::test]
        async fn test_bad_ohttp_keys() -> Result<(), BoxSendSyncError> {
            let bytes = CheckedHrpstring::new::<NoChecksum>(
                "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC",
            )?
            .byte_iter()
            .collect::<Vec<u8>>();
            let bad_ohttp_keys = OhttpKeys::try_from(&bytes[..]).expect("Invalid OhttpKeys");

            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = try_request_with_bad_keys(&services, bad_ohttp_keys) => res
            );

            assert_eq!(
                result?.headers().get("content-type").expect("content type should be present"),
                "application/problem+json"
            );

            async fn try_request_with_bad_keys(
                services: &TestServices,
                bad_ohttp_keys: OhttpKeys,
            ) -> Result<Response, BoxSendSyncError> {
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let mock_address = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")?
                    .assume_checked();
                let persister = InMemoryPersister::default();
                let bad_initializer = ReceiverBuilder::new(
                    mock_address,
                    services.directory_url().as_str(),
                    bad_ohttp_keys,
                )?
                .build()
                .save(&persister)?;
                let (req, _ctx) =
                    bad_initializer.create_poll_request(services.ohttp_relay_url().as_str())?;
                agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await
                    .map_err(|e| e.into())
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_session_expiration() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = do_expiration_tests(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn do_expiration_tests(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                services.wait_for_services_ready().await?;
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let recv_persister = InMemoryPersister::default();
                let send_persister = InMemoryPersister::default();
                // **********************
                // Inside the Receiver:
                let address = receiver.new_address()?;
                // test session with expiration in the past
                let expired_receiver =
                    ReceiverBuilder::new(address, services.directory_url().as_str(), ohttp_keys)?
                        .with_expiration(Duration::from_secs(0))
                        .build()
                        .save(&recv_persister)?;
                match expired_receiver.create_poll_request(services.ohttp_relay_url().as_str()) {
                    // Internal error types are private, so check against a string
                    Err(err) => assert!(err.to_string().contains("expired")),
                    _ => panic!("Expired receive session should error"),
                };

                // **********************
                // Inside the Sender:
                let psbt = build_original_psbt(&sender, &expired_receiver.pj_uri())?;
                // Test that an expired pj_url errors
                let expired_req_ctx = SenderBuilder::new(psbt, expired_receiver.pj_uri())
                    .build_non_incentivizing(FeeRate::BROADCAST_MIN)?
                    .save(&send_persister)?;

                match expired_req_ctx.create_v2_post_request(services.ohttp_relay_url().as_str()) {
                    // Internal error types are private, so check against a string
                    Err(err) => assert!(err.to_string().contains("expired")),
                    _ => panic!("Expired send session should error"),
                };
                Ok(())
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_err_response() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = do_err_test(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn do_err_test(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let persister = InMemoryPersister::default();
                let sender_persister = InMemoryPersister::default();
                // **********************
                // Inside the Receiver:
                let address = receiver.new_address()?;

                let session =
                    ReceiverBuilder::new(address, services.directory_url().as_str(), ohttp_keys)?
                        .build()
                        .save(&persister)?;
                println!("session: {:#?}", session);
                // Poll receive request
                let (req, ctx) =
                    session.create_poll_request(services.ohttp_relay_url().as_str())?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                assert!(response.status().is_success(), "error response: {}", response.status());
                let response_body = session
                    .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                    .save(&persister)?;
                // No proposal yet since sender has not responded
                let session =
                    if let OptionalTransitionOutcome::Stasis(current_state) = response_body {
                        current_state
                    } else {
                        panic!("Should still be in initialized state")
                    };

                // **********************
                // Inside the Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&session.pj_uri().to_string())
                    .map_err(|e| e.to_string())?
                    .assume_checked()
                    .check_pj_supported()
                    .map_err(|e| e.to_string())?;
                let psbt = build_sweep_psbt(&sender, &pj_uri)?;
                let req_ctx = SenderBuilder::new(psbt, pj_uri)
                    .build_recommended(FeeRate::BROADCAST_MIN)?
                    .save(&sender_persister)?;
                let (Request { url, body, content_type, .. }, send_ctx) =
                    req_ctx.create_v2_post_request(services.ohttp_relay_url().as_str())?;
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                tracing::info!("Response: {:#?}", &response);
                assert!(response.status().is_success(), "error response: {}", response.status());
                let req_ctx = req_ctx
                    .process_response(&response.bytes().await?, send_ctx)
                    .save(&sender_persister)?;

                // POST Original PSBT

                // **********************
                // Inside the Receiver:

                // GET fallback psbt
                let (req, ctx) =
                    session.create_poll_request(services.ohttp_relay_url().as_str())?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                // POST payjoin
                let outcome = session
                    .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                    .save(&persister)?;
                let proposal = if let OptionalTransitionOutcome::Progress(psbt) = outcome {
                    psbt
                } else {
                    panic!("proposal should exist");
                };

                // Progress past the first typestate so we can send a encrypted error response
                // TODO: when the reply key is being persisted as its own session event we can fail at the
                // unchecked original typestate
                let proposal = proposal.assume_interactive_receiver().save(&persister)?;

                // Generate replyable error
                let server_error = proposal
                    .clone()
                    .check_inputs_not_owned(&mut |_| Ok(true))
                    .save(&persister)
                    .expect_err("should fail")
                    .api_error()
                    .expect("expected api error");
                // TODO: this should be replaced by comparing the error itself once the error types impl PartialEq
                // Issue: https://github.com/payjoin/rust-payjoin/issues/645
                assert_eq!(
                    server_error.to_string(),
                    "Protocol error: The receiver rejected the original PSBT."
                );

                let (session, session_history) = replay_receiver_event_log(&persister)?;
                assert_eq!(session_history.status(), SessionStatus::Active);
                let has_error = match session {
                    ReceiveSession::HasReplyableError(r) => r,
                    _ => panic!("Expected HasError"),
                };
                let (err_req, err_ctx) =
                    has_error.create_error_request(services.ohttp_relay_url().as_str())?;
                let err_response = agent
                    .post(err_req.url)
                    .header("Content-Type", err_req.content_type)
                    .body(err_req.body)
                    .send()
                    .await?;

                let err_bytes = err_response.bytes().await?;
                has_error.process_error_response(&err_bytes, err_ctx).save(&persister)?;

                // Ensure the session is closed properly
                let (_, session_history) = replay_receiver_event_log(&persister)?;
                assert_eq!(session_history.status(), SessionStatus::Failed);

                // Check that we can read the error response as a sender
                let (req, ctx) =
                    req_ctx.create_poll_request(services.ohttp_relay_url().as_str())?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                assert!(response.status().is_success(), "error response: {}", response.status());
                let reply_error = req_ctx
                    .process_response(&response.bytes().await?, ctx)
                    .save(&sender_persister)
                    .expect_err("Should be a fatal error");

                let api_error = reply_error.api_error().expect("expecting error from API");
                match api_error {
                    ResponseError::WellKnown(well_known_error) => {
                        assert_eq!(
                            well_known_error.to_string(),
                            "The receiver rejected the original PSBT."
                        );
                    }
                    _ => panic!("Expected Unrecognized error, got {:?}", api_error),
                }

                Ok(())
            }

            Ok(())
        }

        #[tokio::test]
        async fn v2_to_v2_p2pkh() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_LEGACY_WEIGHT + (P2PKH_INPUT_WEIGHT * 2) + P2WPKH_OUTPUT_WEIGHT,
            )
            // bitcoin-cli wallet uses signature grinding to save one vbyte on the original PSBT.
            // subtract it here
            - Weight::from_vb_unchecked(1);
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;

            let (_bitcoind, sender, receiver) =
                init_bitcoind_sender_receiver(Some(AddressType::Legacy), Some(AddressType::Legacy))
                    .expect("should be able to initialize the sender and the receiver");
            let recv_persister = InMemoryPersister::default();
            let send_persister = InMemoryPersister::default();

            let result = tokio::select!(
                err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
                err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
                res = do_v2_to_v2(&services, &receiver, &sender, &recv_persister, &send_persister, SenderFinalAction::SignAndBroadcastPayjoinProposal) => res
            );

            assert!(result.is_ok(), "v2 p2pkh send receive failed: {:#?}", result.unwrap_err());

            let (broadcasted_transaction, monitoring_payment) = result.unwrap();

            // Sender should have sent the entire value of their UTXO to receiver (minus fees).
            assert_eq!(broadcasted_transaction.input.len(), 2);
            assert_eq!(broadcasted_transaction.output.len(), 1);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(100.0)? - expected_fee
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.0)?
            );

            // Receiver cannot validate that the sender has broadcasted the Payjoin proposal or the fallback transaction.
            // The sender is using a non-SegWit address, so their signature is going to change the TXID. So we test whether the
            // function exists early and does not call the closure.
            monitoring_payment
                .check_payment(|_| {
                    panic!("when the sender is using a non-SegWit address type, the check_payment function should skip the check and return success")
                })
                .save(&recv_persister)
                .expect("receiver should successfully monitor for the payment");

            let (_session, session_history) = replay_receiver_event_log(&recv_persister)?;
            assert_eq!(
                recv_persister.load().unwrap().last(),
                Some(payjoin::receive::v2::SessionEvent::Closed(payjoin::receive::v2::SessionOutcome::PayjoinProposalSent)),
                "The last event of the persister should be a SessionOutcome::PayjoinProposalSent since the sender is going to change the TXID when they sign the Payjoin proposal",
            );
            assert_eq!(session_history.status(), SessionStatus::Completed);
            Ok(())
        }

        #[tokio::test]
        async fn v2_to_v2_p2wpkh() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + P2WPKH_OUTPUT_WEIGHT,
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;

            let (_bitcoind, sender, receiver) =
                init_bitcoind_sender_receiver(Some(AddressType::Bech32), Some(AddressType::Bech32))
                    .expect("should be able to initialize the sender and the receiver");
            let recv_persister = InMemoryPersister::default();
            let send_persister = InMemoryPersister::default();

            let result = tokio::select!(
                err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
                err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
                res = do_v2_to_v2(&services, &receiver, &sender, &recv_persister, &send_persister, SenderFinalAction::SignAndBroadcastPayjoinProposal) => res
            );

            assert!(result.is_ok(), "v2 p2wpkh send receive failed: {:#?}", result.unwrap_err());

            let (broadcasted_transaction, monitoring_payment) = result.unwrap();

            // Sender should have sent the entire value of their UTXO to receiver (minus fees).
            assert_eq!(broadcasted_transaction.input.len(), 2);
            assert_eq!(broadcasted_transaction.output.len(), 1);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(100.0)? - expected_fee
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.0)?
            );

            // Receiver should be able to validate that the sender has broadcasted the Payjoin proposal.
            monitoring_payment
                .check_payment(|txid| {
                    let get_tx_result = receiver.get_raw_transaction(txid);
                    match get_tx_result {
                        Ok(tx) =>
                            Ok(Some(tx.transaction().expect("transaction should be decodable"))),
                        Err(_) => {
                            panic!("should be able to find the payjoin proposal broadcasted")
                        }
                    }
                })
                .save(&recv_persister)
                .expect("receiver should successfully monitor for the payment");

            // Receiver session should have completed with a Success, along with information on the
            // sender signatures on the Payjoin that was broadcasted.
            let (_session, session_history) = replay_receiver_event_log(&recv_persister)?;
            let sender_outpoint = session_history.fallback_tx().unwrap().input[0].previous_output;
            let sender_signatures = {
                let sender_txin = broadcasted_transaction
                    .input
                    .iter()
                    .find(|txin| txin.previous_output == sender_outpoint)
                    .expect("sender input must be present in payjoin_tx")
                    .clone();
                vec![(sender_txin.clone().script_sig, sender_txin.clone().witness)]
            };
            assert_eq!(
                recv_persister.load().unwrap().last(),
                Some(payjoin::receive::v2::SessionEvent::Closed(payjoin::receive::v2::SessionOutcome::Success(sender_signatures))),
                "The last event of the persister should be a SessionOutcome::Success with the correct sender signature",
            );
            assert_eq!(session_history.status(), SessionStatus::Completed);
            Ok(())
        }

        #[tokio::test]
        async fn v2_to_v2_taproot() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT
                    + (P2TR_INPUT_WEIGHT * 2)
                    + P2WPKH_OUTPUT_WEIGHT,
            )
            // bitcoin-cli wallet overestimates taproot inputs in the original PSBT by one vbyte:
            // https://github.com/payjoin/rust-payjoin/issues/369#issuecomment-2657539591
            // add it here
            + Weight::from_vb_unchecked(1);
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;

            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32m),
                Some(AddressType::Bech32m),
            )
            .expect("should be able to initialize the sender and the receiver");
            let recv_persister = InMemoryPersister::default();
            let send_persister = InMemoryPersister::default();

            let result = tokio::select!(
                err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
                err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
                res = do_v2_to_v2(&services, &receiver, &sender, &recv_persister, &send_persister, SenderFinalAction::SignAndBroadcastPayjoinProposal) => res
            );

            assert!(result.is_ok(), "v2 taproot send receive failed: {:#?}", result.unwrap_err());

            let (broadcasted_transaction, monitoring_payment) = result.unwrap();

            // Sender should have sent the entire value of their UTXO to receiver (minus fees).
            assert_eq!(broadcasted_transaction.input.len(), 2);
            assert_eq!(broadcasted_transaction.output.len(), 1);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(100.0)? - expected_fee
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.0)?
            );

            // Receiver should be able to validate that the sender has broadcasted the Payjoin proposal.
            monitoring_payment
                .check_payment(|txid| {
                    let get_tx_result = receiver.get_raw_transaction(txid);
                    match get_tx_result {
                        Ok(tx) =>
                            Ok(Some(tx.transaction().expect("transaction should be decodable"))),
                        Err(_) => {
                            panic!("should be able to find the payjoin proposal broadcasted")
                        }
                    }
                })
                .save(&recv_persister)
                .expect("receiver should successfully monitor for the payment");

            // Receiver session should have completed with a Success, along with information on the
            // sender signatures on the Payjoin that was broadcasted.
            let (_session, session_history) = replay_receiver_event_log(&recv_persister)?;
            let sender_outpoint = session_history.fallback_tx().unwrap().input[0].previous_output;
            let sender_signatures = {
                let sender_txin = broadcasted_transaction
                    .input
                    .iter()
                    .find(|txin| txin.previous_output == sender_outpoint)
                    .expect("sender input must be present in payjoin_tx")
                    .clone();
                vec![(sender_txin.clone().script_sig, sender_txin.clone().witness)]
            };
            assert_eq!(
                recv_persister.load().unwrap().last(),
                Some(payjoin::receive::v2::SessionEvent::Closed(payjoin::receive::v2::SessionOutcome::Success(sender_signatures))),
                "The last event of the persister should be a SessionOutcome::Success with the correct sender signature",
            );
            assert_eq!(session_history.status(), SessionStatus::Completed);
            Ok(())
        }

        #[tokio::test]
        async fn v2_to_v2_fallback_tx_broadcast() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let expected_weight =
                Weight::from_wu(TX_HEADER_WEIGHT + P2WPKH_INPUT_WEIGHT + P2WPKH_OUTPUT_WEIGHT);
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;

            let (_bitcoind, sender, receiver) =
                init_bitcoind_sender_receiver(Some(AddressType::Bech32), Some(AddressType::Bech32))
                    .expect("should be able to initialize the sender and the receiver");
            let recv_persister = InMemoryPersister::default();
            let send_persister = InMemoryPersister::default();

            let result = tokio::select!(
                err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
                err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
                res = do_v2_to_v2(&services, &receiver, &sender, &recv_persister, &send_persister, SenderFinalAction::BroadcastFallbackTransaction) => res
            );

            assert!(
                result.is_ok(),
                "v2 send receive with fallback broadcast failed: {:#?}",
                result.unwrap_err()
            );

            let (broadcasted_transaction, monitoring_payment) = result.unwrap();

            // Fallback transaction was broadcasted, so there will only be a single input.
            assert_eq!(broadcasted_transaction.input.len(), 1);
            assert_eq!(broadcasted_transaction.output.len(), 1);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(50.0)? - expected_fee
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.0)?
            );

            // Receiver should be able to validate that the sender has broadcasted the fallback transaction.
            // The check_payment closure should be called twice: first for the Payjoin proposal, which will not be found,
            // and then for the fallback transaction, which will be found..
            monitoring_payment
                .check_payment(|txid| {
                    let get_tx_result = receiver.get_raw_transaction(txid);
                    match get_tx_result {
                        Ok(tx) =>
                            Ok(Some(tx.transaction().expect("transaction should be decodable"))),
                        Err(_) => Ok(None),
                    }
                })
                .save(&recv_persister)
                .expect("receiver should successfully monitor for the payment");

            // Receiver session should have completed with a Success and a fallback session
            // outcome.
            let (_session, session_history) = replay_receiver_event_log(&recv_persister)?;
            assert_eq!(
                recv_persister.load().unwrap().last(),
                Some(payjoin::receive::v2::SessionEvent::Closed(payjoin::receive::v2::SessionOutcome::FallbackBroadcasted)),
                "The last event of the persister should be a SessionOutcome::Success with the correct sender signature",
            );
            assert_eq!(session_history.status(), SessionStatus::FallbackBroadcasted);
            Ok(())
        }

        /// Helper function for running a Payjoin v2 session. Uses the `sender_final_action`
        /// parameter to determine what action the sender will take after they receive the Payjoin
        /// proposal from the receiver.
        ///
        /// Returns the transaction which the sender broadcasts and the state of the Receiver
        /// before they begin monitoring ([`Receiver<Monitor>`]) so that different tests can modify
        /// how the receiver is going to validate the action the sender takes.
        async fn do_v2_to_v2<R, S>(
            services: &TestServices,
            receiver: &corepc_node::Client,
            sender: &corepc_node::Client,
            recv_persister: &R,
            send_persister: &S,
            sender_final_action: SenderFinalAction,
        ) -> Result<(Transaction, Receiver<Monitor>), BoxError>
        where
            R: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone,
            S: SessionPersister<SessionEvent = payjoin::send::v2::SessionEvent> + Clone,
        {
            let agent = services.http_agent();
            services.wait_for_services_ready().await?;
            let ohttp_keys = services.fetch_ohttp_keys().await?;
            // **********************
            // Inside the Receiver:
            let address = receiver.new_address()?;

            // test session with expiration in the future
            let session =
                ReceiverBuilder::new(address, services.directory_url().as_str(), ohttp_keys)?
                    .build()
                    .save(recv_persister)?;
            println!("session: {:#?}", session);
            // Poll receive request
            let (req, ctx) = session.create_poll_request(services.ohttp_relay_url().as_str())?;
            let response = agent
                .post(req.url)
                .header("Content-Type", req.content_type)
                .body(req.body)
                .send()
                .await?;
            assert!(response.status().is_success(), "error response: {}", response.status());
            let response_body = session
                .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                .save(recv_persister)?;
            // No proposal yet since sender has not responded
            let session = if let OptionalTransitionOutcome::Stasis(current_state) = response_body {
                current_state
            } else {
                panic!("Should still be in initialized state")
            };

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri = Uri::from_str(&session.pj_uri().to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_sweep_psbt(sender, &pj_uri)?;
            let req_ctx = SenderBuilder::new(psbt, pj_uri)
                .build_recommended(FeeRate::BROADCAST_MIN)?
                .save(send_persister)?;
            let (Request { url, body, content_type, .. }, send_ctx) =
                req_ctx.create_v2_post_request(services.ohttp_relay_url().as_str())?;
            let response =
                agent.post(url).header("Content-Type", content_type).body(body).send().await?;
            tracing::info!("Response: {:#?}", &response);
            assert!(response.status().is_success(), "error response: {}", response.status());
            let send_ctx = req_ctx
                .process_response(&response.bytes().await?, send_ctx)
                .save(send_persister)?;
            // POST Original PSBT

            // **********************
            // Inside the Receiver:

            // GET fallback psbt
            let (req, ctx) = session.create_poll_request(services.ohttp_relay_url().as_str())?;
            let response = agent
                .post(req.url)
                .header("Content-Type", req.content_type)
                .body(req.body)
                .send()
                .await?;
            // POST payjoin
            let outcome = session
                .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                .save(recv_persister)?;
            let proposal = if let OptionalTransitionOutcome::Progress(psbt) = outcome {
                psbt
            } else {
                panic!("proposal should exist");
            };
            let payjoin_proposal =
                handle_directory_proposal(receiver, proposal, recv_persister, None)?;
            let (req, ctx) =
                payjoin_proposal.create_post_request(services.ohttp_relay_url().as_str())?;
            let response = agent
                .post(req.url)
                .header("Content-Type", req.content_type)
                .body(req.body)
                .send()
                .await?;
            let monitoring_payment = payjoin_proposal
                .process_response(&response.bytes().await?, ctx)
                .save(recv_persister)?;

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, constructs, and broadcasts
            // Replay post fallback to get the response
            let (Request { url, body, content_type, .. }, ohttp_ctx) =
                send_ctx.create_poll_request(services.ohttp_relay_url().as_str())?;
            let response =
                agent.post(url).header("Content-Type", content_type).body(body).send().await?;
            tracing::info!("Response: {:#?}", &response);
            let response = send_ctx
                .process_response(&response.bytes().await?, ohttp_ctx)
                .save(send_persister)
                .expect("psbt should exist");

            let checked_payjoin_proposal_psbt =
                if let OptionalTransitionOutcome::Progress(psbt) = response {
                    psbt
                } else {
                    panic!("psbt should exist");
                };

            let broadcasted_transaction = match sender_final_action {
                SenderFinalAction::SignAndBroadcastPayjoinProposal =>
                    extract_pj_tx(sender, checked_payjoin_proposal_psbt.clone())?,
                SenderFinalAction::BroadcastFallbackTransaction =>
                    replay_sender_event_log(send_persister)?.1.fallback_tx(),
            };
            sender.send_raw_transaction(&broadcasted_transaction)?;
            Ok((broadcasted_transaction, monitoring_payment))
        }

        #[test]
        fn v2_to_v1() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            // FIXME this test no longer sends v2 to v1 because that concept is gone and should now be
            // Handled by the implementation. Therefore, the e2e test should now test v2-capable sender
            // successfully sending to v1.
            assert!(matches!(pj_uri.extras.pj_param(), payjoin::PjParam::V1(_)));
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            let req_ctx = payjoin::send::v1::SenderBuilder::new(psbt, pj_uri)
                .build_recommended(FeeRate::BROADCAST_MIN)?;
            let (req, ctx) = req_ctx.create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_v1_pj_request(req, headers, &receiver, None, None, None)?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, constructs, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            assert_eq!(payjoin_tx.input.len(), 2);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(51.0)?
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - network_fees
            );
            Ok(())
        }

        #[tokio::test]
        async fn v1_to_v2() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = do_v1_to_v2(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn do_v1_to_v2(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let recv_persister = InMemoryPersister::default();
                let address = receiver.new_address()?;
                let session = ReceiverBuilder::new(
                    address,
                    services.directory_url().as_str(),
                    ohttp_keys.clone(),
                )?
                .build()
                .save(&recv_persister)?;

                // **********************
                // Inside the V1 Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&session.pj_uri().to_string())
                    .map_err(|e| e.to_string())?
                    .assume_checked()
                    .check_pj_supported()
                    .map_err(|e| e.to_string())?;
                let psbt = build_original_psbt(&sender, &pj_uri)?;
                let req_ctx = payjoin::send::v1::SenderBuilder::new(psbt, pj_uri)
                    .build_with_additional_fee(
                        Amount::from_sat(10000),
                        None,
                        FeeRate::ZERO,
                        false,
                    )?;
                let (Request { url, body, content_type, .. }, send_ctx) =
                    req_ctx.create_v1_post_request();
                tracing::info!("send fallback v1 to offline receiver fail");
                let res = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await;
                assert!(res?.status() == StatusCode::SERVICE_UNAVAILABLE);

                // **********************
                // Inside the Receiver:
                let agent_clone: Arc<Client> = agent.clone();
                let receiver: Arc<corepc_node::Client> = Arc::new(receiver);
                let receiver_clone = receiver.clone();
                let ohttp_relay = services.ohttp_relay_url().to_string();
                let receiver_loop = tokio::task::spawn(async move {
                    let agent_clone = agent_clone.clone();
                    let proposal = loop {
                        let (req, ctx) = session.create_poll_request(&ohttp_relay)?;
                        let response = agent_clone
                            .post(req.url)
                            .header("Content-Type", req.content_type)
                            .body(req.body)
                            .send()
                            .await?;

                        if response.status() == 200 {
                            let proposal = session
                                .clone()
                                .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                                .save(&recv_persister)?;
                            if let OptionalTransitionOutcome::Progress(unchecked_proposal) =
                                proposal
                            {
                                break unchecked_proposal.clone();
                            } else {
                                tracing::info!(
                                    "No response yet for POST payjoin request, retrying some seconds"
                                );
                            }
                        } else {
                            tracing::error!("Unexpected response status: {}", response.status());
                            panic!("Unexpected response status: {}", response.status())
                        }
                    };
                    let payjoin_proposal =
                        handle_directory_proposal(&receiver_clone, proposal, &recv_persister, None)
                            .map_err(|e| e.to_string())?;
                    // Respond with payjoin psbt within the time window the sender is willing to wait
                    // this response would be returned as http response to the sender
                    let (req, ctx) = payjoin_proposal.create_post_request(ohttp_relay)?;
                    let response = agent_clone
                        .post(req.url)
                        .header("Content-Type", req.content_type)
                        .body(req.body)
                        .send()
                        .await?;
                    payjoin_proposal
                        .process_response(&response.bytes().await?, ctx)
                        .save(&recv_persister)
                        .map_err(|e| e.to_string())?;
                    Ok::<_, BoxSendSyncError>(())
                });

                // **********************
                // send fallback v1 to online receiver
                tracing::info!("send fallback v1 to online receiver should succeed");
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                tracing::info!("Response: {:#?}", &response);
                assert!(response.status().is_success(), "error response: {}", response.status());

                let checked_payjoin_proposal_psbt =
                    send_ctx.process_response(&response.bytes().await?)?;
                let network_fees = checked_payjoin_proposal_psbt.fee()?;
                let expected_weight = Weight::from_wu(
                    TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
                );
                let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
                assert_eq!(network_fees, expected_fee);
                let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
                sender.send_raw_transaction(&payjoin_tx)?;
                tracing::info!("sent");
                assert!(
                    receiver_loop.await.is_ok(),
                    "The spawned task panicked or returned an error"
                );

                // Check resulting transaction and balances
                assert_eq!(payjoin_tx.input.len(), 2);
                assert_eq!(payjoin_tx.output.len(), 2);
                assert_eq!(
                    receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                    Amount::from_btc(51.0)?
                );
                assert_eq!(
                    sender.get_balances()?.into_model()?.mine.untrusted_pending,
                    Amount::from_btc(49.0)? - network_fees
                );
                Ok(())
            }

            Ok(())
        }

        fn handle_directory_proposal(
            receiver: &corepc_node::Client,
            proposal: Receiver<UncheckedOriginalPayload>,
            recv_persister: &impl SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>,
            custom_inputs: Option<Vec<InputPair>>,
        ) -> Result<Receiver<PayjoinProposal>, BoxError> {
            // Receive Check 1: Can Broadcast
            let proposal = proposal
                .check_broadcast_suitability(None, |tx| {
                    Ok(receiver
                        .test_mempool_accept(std::slice::from_ref(tx))
                        .map_err(ImplementationError::new)?
                        .0
                        .first()
                        .ok_or(ImplementationError::from(
                            "testmempoolaccept should return a result",
                        ))?
                        .allowed)
                })
                .save(recv_persister)?;

            // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
            let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

            // Receive Check 2: receiver can't sign for proposal inputs
            let proposal = proposal
                .check_inputs_not_owned(&mut |input| {
                    let address = bitcoin::Address::from_script(input, bitcoin::Network::Regtest)
                        .map_err(ImplementationError::new)?;
                    receiver
                        .get_address_info(&address)
                        .map(|info| info.is_mine)
                        .map_err(ImplementationError::new)
                })
                .save(recv_persister)?;

            // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
            let payjoin = proposal
                .check_no_inputs_seen_before(&mut |_| Ok(false))
                .save(recv_persister)?
                .identify_receiver_outputs(&mut |output_script| {
                    let address =
                        bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                            .map_err(ImplementationError::new)?;
                    receiver
                        .get_address_info(&address)
                        .map(|info| info.is_mine)
                        .map_err(ImplementationError::new)
                })
                .save(recv_persister)?;

            let payjoin = payjoin.commit_outputs().save(recv_persister)?;

            let inputs = match custom_inputs {
                Some(inputs) => inputs,
                None => {
                    let candidate_inputs = receiver
                        .list_unspent()
                        .map_err(ImplementationError::new)?
                        .0
                        .into_iter()
                        .map(input_pair_from_list_unspent);
                    let selected_input =
                        payjoin.try_preserving_privacy(candidate_inputs).map_err(|e| {
                            format!("Failed to make privacy preserving selection: {e:?}")
                        })?;
                    vec![selected_input]
                }
            };
            let payjoin = payjoin
                .contribute_inputs(inputs)
                .map_err(|e| format!("Failed to contribute inputs: {e:?}"))?
                .commit_inputs()
                .save(recv_persister)?;

            let payjoin = payjoin
                .apply_fee_range(
                    Some(FeeRate::BROADCAST_MIN),
                    Some(FeeRate::from_sat_per_vb_u32(2)),
                )
                .save(recv_persister)?;

            // Sign and finalize the proposal PSBT
            let payjoin = payjoin
                .finalize_proposal(|psbt: &Psbt| {
                    receiver
                        // call RPC manually to pass custom options
                        .call::<corepc_node::vtype::WalletProcessPsbt>(
                            "walletprocesspsbt",
                            &[
                                json!(psbt.to_string()),
                                json!(None as Option<bool>),
                                json!(None as Option<&str>),
                                json!(Some(true)), // check that the receiver properly clears keypaths
                            ],
                        )
                        .map(|res| Psbt::from_str(&res.psbt).expect("psbt should be valid"))
                        .map_err(ImplementationError::new)
                })
                .save(recv_persister)?;
            Ok(payjoin)
        }

        pub fn build_sweep_psbt(
            sender: &corepc_node::Client,
            pj_uri: &PjUri,
        ) -> Result<Psbt, BoxError> {
            let mut outputs = HashMap::with_capacity(1);
            outputs.insert(pj_uri.address.to_string(), Amount::from_btc(50.0)?.to_btc());
            let options = serde_json::json!({
                "lockUnspents": true,
                // The minimum relay feerate ensures that tests fail if the receiver would add inputs/outputs
                // that cannot be covered by the sender's additional fee contributions.
                "feeRate": Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into()).to_btc(),
                "subtractFeeFromOutputs": [0],
            });
            let psbt = sender
                // call RPC manually to pass custom options
                .call::<corepc_node::vtype::WalletCreateFundedPsbt>(
                    "walletcreatefundedpsbt",
                    &[
                        json!(&[] as &[serde_json::Value]), // inputs
                        json!(&outputs),
                        json!(None as Option<u64>), // locktime
                        json!(options),
                        json!(Some(true)), // check that the sender properly clears keypaths
                    ],
                )?
                .psbt;
            let psbt = sender.wallet_process_psbt(&Psbt::from_str(&psbt)?)?.psbt;
            Ok(Psbt::from_str(&psbt)?)
        }
    }

    #[cfg(feature = "v1")]
    mod batching {
        use payjoin::send::v1::SenderBuilder;
        use payjoin::UriExt;

        use super::*;

        // In this test the receiver consolidates a bunch of UTXOs into the destination output
        #[test]
        fn receiver_consolidates_utxos() -> Result<(), BoxError> {
            init_tracing();
            let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            // Generate more UTXOs for the receiver
            let receiver_address = receiver.new_address_with_type(AddressType::Bech32)?;
            bitcoind.client.generate_to_address(199, &receiver_address)?;
            let receiver_utxos = receiver.list_unspent()?.0;
            assert_eq!(100, receiver_utxos.len(), "receiver doesn't have enough UTXOs");
            assert_eq!(
                Amount::from_btc(3650.0)?, // 50 (starting receiver balance) + 46*50.0 + 52*25.0 (halving occurs every 150 blocks)
                receiver.get_balances()?.into_model()?.mine.trusted,
                "receiver doesn't have enough bitcoin"
            );

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            tracing::debug!("Original psbt: {psbt:#?}");
            let max_additional_fee = Amount::from_sat(1000);
            let (req, ctx) = SenderBuilder::new(psbt.clone(), uri)
                .build_with_additional_fee(max_additional_fee, None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let outputs = vec![TxOut {
                value: Amount::from_btc(3650.0)?,
                script_pubkey: receiver.new_address()?.script_pubkey(),
            }];
            let drain_script = outputs[0].script_pubkey.clone();
            let inputs = receiver_utxos.into_iter().map(input_pair_from_list_unspent).collect();
            let response = handle_v1_pj_request(
                req,
                headers,
                &receiver,
                Some(outputs),
                Some(&drain_script),
                Some(inputs),
            )?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 101) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            // The sender pays (original tx fee + max additional fee)
            let original_tx_fee = psbt.fee()?;
            let sender_fee = original_tx_fee + max_additional_fee;
            // The receiver pays the difference
            let receiver_fee = network_fees - sender_fee;
            assert_eq!(payjoin_tx.input.len(), 101);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(3651.0)? - receiver_fee
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - sender_fee
            );
            Ok(())
        }

        // In this test the receiver forwards part of the sender payment to another payee
        #[test]
        fn receiver_forwards_payment() -> Result<(), BoxError> {
            init_tracing();
            let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            let third_party = bitcoind.create_wallet("third-party")?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            tracing::debug!("Original psbt: {psbt:#?}");
            let (req, ctx) = SenderBuilder::new(psbt.clone(), uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let outputs = vec![
                TxOut {
                    value: Amount::from_sat(10000000),
                    script_pubkey: third_party.new_address()?.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(90000000),
                    script_pubkey: receiver.new_address()?.script_pubkey(),
                },
            ];
            let drain_script = outputs[1].script_pubkey.clone();
            let inputs = vec![];
            let response = handle_v1_pj_request(
                req,
                headers,
                &receiver,
                Some(outputs),
                Some(&drain_script),
                Some(inputs),
            )?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT) + (P2WPKH_OUTPUT_WEIGHT * 3),
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            // The sender pays original tx fee
            let original_tx_fee = psbt.fee()?;
            let sender_fee = original_tx_fee;
            // The receiver pays the difference
            let receiver_fee = network_fees - sender_fee;
            assert_eq!(payjoin_tx.input.len(), 1);
            assert_eq!(payjoin_tx.output.len(), 3);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.9)? - receiver_fee
            );
            assert_eq!(
                third_party.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.1)?
            );
            // sender balance is considered "trusted" because all inputs in the transaction were
            // created by their wallet
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.trusted,
                Amount::from_btc(49.0)? - sender_fee
            );
            Ok(())
        }
    }

    fn build_original_psbt(sender: &corepc_node::Client, pj_uri: &PjUri) -> Result<Psbt, BoxError> {
        let mut outputs = HashMap::with_capacity(1);
        outputs
            .insert(pj_uri.address.to_string(), pj_uri.amount.unwrap_or(Amount::ONE_BTC).to_btc());
        let options = json!({
            "lockUnspents": true,
            // The minimum relay feerate ensures that tests fail if the receiver would add inputs/outputs
            // that cannot be covered by the sender's additional fee contributions.
            "feeRate": Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into()).to_btc(),
        });
        let psbt = sender
            // call RPC manually to pass custom options
            .call::<corepc_node::vtype::WalletCreateFundedPsbt>(
                "walletcreatefundedpsbt",
                &[
                    json!(&[] as &[serde_json::Value]), // inputs
                    json!(&outputs),
                    json!(None as Option<u64>), // locktime
                    json!(options),
                    json!(Some(true)), // check that the sender properly clears keypaths
                ],
            )?
            .psbt;
        let psbt = sender.wallet_process_psbt(&Psbt::from_str(&psbt)?)?.psbt;
        Ok(Psbt::from_str(&psbt)?)
    }

    // Receiver receive and process original_psbt from a sender
    // In production it it will come in as an HTTP request (over ssl or onion)
    fn handle_v1_pj_request(
        req: Request,
        headers: impl payjoin::receive::v1::Headers,
        receiver: &corepc_node::Client,
        custom_outputs: Option<Vec<TxOut>>,
        drain_script: Option<&bitcoin::Script>,
        custom_inputs: Option<Vec<InputPair>>,
    ) -> Result<String, BoxError> {
        // Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
        let proposal = payjoin::receive::v1::UncheckedOriginalPayload::from_request(
            req.body.as_slice(),
            Url::from_str(&req.url).expect("Could not parse url").query().unwrap_or(""),
            headers,
        )?;
        let proposal =
            handle_proposal(proposal, receiver, custom_outputs, drain_script, custom_inputs)?;
        let psbt = proposal.psbt();
        tracing::debug!("Receiver's Payjoin proposal PSBT: {psbt:#?}");
        Ok(psbt.to_string())
    }

    fn handle_proposal(
        proposal: payjoin::receive::v1::UncheckedOriginalPayload,
        receiver: &corepc_node::Client,
        custom_outputs: Option<Vec<TxOut>>,
        drain_script: Option<&bitcoin::Script>,
        custom_inputs: Option<Vec<InputPair>>,
    ) -> Result<payjoin::receive::v1::PayjoinProposal, BoxError> {
        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
            Ok(receiver
                .test_mempool_accept(std::slice::from_ref(tx))
                .map_err(ImplementationError::new)?
                .0
                .first()
                .ok_or(ImplementationError::from("testmempoolaccept should return a result"))?
                .allowed)
        })?;
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(&mut |input| {
            let address = bitcoin::Address::from_script(input, bitcoin::Network::Regtest)
                .map_err(ImplementationError::new)?;
            receiver
                .get_address_info(&address)
                .map(|info| info.is_mine)
                .map_err(ImplementationError::new)
        })?;

        // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal
            .check_no_inputs_seen_before(&mut |_| Ok(false))?
            .identify_receiver_outputs(&mut |output_script| {
                let address =
                    bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                        .map_err(ImplementationError::new)?;
                receiver
                    .get_address_info(&address)
                    .map(|info| info.is_mine)
                    .map_err(ImplementationError::new)
            })?;

        let payjoin = match custom_outputs {
            Some(txos) => payjoin.replace_receiver_outputs(
                txos,
                drain_script.expect("drain_script should be provided with custom_outputs"),
            )?,
            None => payjoin.substitute_receiver_script(&receiver.new_address()?.script_pubkey())?,
        }
        .commit_outputs();

        let inputs = match custom_inputs {
            Some(inputs) => inputs,
            None => {
                let candidate_inputs =
                    receiver.list_unspent()?.0.into_iter().map(input_pair_from_list_unspent);
                let selected_input = payjoin
                    .try_preserving_privacy(candidate_inputs)
                    .map_err(|e| format!("Failed to make privacy preserving selection: {e:?}"))?;
                vec![selected_input]
            }
        };
        let payjoin = payjoin
            .contribute_inputs(inputs)
            .map_err(|e| format!("Failed to contribute inputs: {e:?}"))?
            .commit_inputs();
        let payjoin = payjoin
            .apply_fee_range(Some(FeeRate::BROADCAST_MIN), Some(FeeRate::from_sat_per_vb_u32(2)))?;

        let payjoin_proposal = payjoin.finalize_proposal(|psbt: &Psbt| {
            receiver
                // call RPC manually to pass custom options
                .call::<corepc_node::vtype::WalletProcessPsbt>(
                    "walletprocesspsbt",
                    &[
                        json!(psbt.to_string()),
                        json!(None as Option<bool>),
                        json!(None as Option<&str>),
                        json!(Some(true)), // check that the receiver properly clears keypaths
                    ],
                )
                .map(|res| Psbt::from_str(&res.psbt).expect("psbt should be valid"))
                .map_err(ImplementationError::new)
        })?;
        Ok(payjoin_proposal)
    }

    fn extract_pj_tx(
        sender: &corepc_node::Client,
        psbt: Psbt,
    ) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
        let payjoin_psbt = sender.wallet_process_psbt(&psbt)?.psbt;
        let payjoin_psbt = sender
            .finalize_psbt(&Psbt::from_str(&payjoin_psbt)?)?
            .psbt
            .expect("should contain a PSBT");
        let payjoin_psbt = Psbt::from_str(&payjoin_psbt)?;
        tracing::debug!("Sender's Payjoin PSBT: {payjoin_psbt:#?}");

        Ok(payjoin_psbt.extract_tx()?)
    }

    fn input_pair_from_list_unspent(utxo: ListUnspentItem) -> InputPair {
        let utxo = utxo.into_model().expect("listunspent utxo should be convertible to model type");
        let script_pubkey = utxo.script_pubkey.clone();
        let psbtin = PsbtInput {
            // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
            // witness_utxo, even for non-witness inputs
            witness_utxo: Some(TxOut {
                value: utxo.amount.to_unsigned().expect("amount should be unsigned"),
                script_pubkey: utxo.script_pubkey,
            }),
            redeem_script: utxo.redeem_script,
            //FIXME needs later corepc_node bitcoin version
            //witness_script: utxo.witness_script.clone(),
            ..Default::default()
        };
        let txin = TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            ..Default::default()
        };
        // P2TR without witness requires explicit weight (spend type unknown until signing)
        let expected_weight =
            if script_pubkey.is_p2tr() { Some(Weight::from_wu(P2TR_INPUT_WEIGHT)) } else { None };
        InputPair::new(txin, psbtin, expected_weight).expect("Input pair should be valid")
    }

    struct HeaderMock(HashMap<String, String>);

    impl payjoin::receive::v1::Headers for HeaderMock {
        fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key).map(|e| e.as_str()) }
    }

    impl HeaderMock {
        fn new(body: &[u8], content_type: &str) -> HeaderMock {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), content_type.to_string());
            h.insert("content-length".to_string(), body.len().to_string());
            HeaderMock(h)
        }
    }
}
