//! Dedicated completion of one original durable, server-bound creation intent.
use super::initial::SharedClock;
use super::*;

/// Dedicated original-owner publication refusal. Server unknown outcomes retain
/// Foyer's Reconcile status instead of being flattened into rejected authority.
#[derive(Debug)]
pub enum InitialPublicationError {
    Initial(cvlt::InitialError),
    Foyer(cfyr::Error),
}
impl From<cvlt::InitialError> for InitialPublicationError {
    fn from(error: cvlt::InitialError) -> Self {
        Self::Initial(error)
    }
}

fn refused() -> cvlt::InitialError {
    cvlt::InitialError::Keys(Error::Unauthorized)
}

/// Reopen the exact original incomplete operation from one inseparable Passkeys
/// assertion/PRF result and its current same-key enrollment owner. Missing data
/// never creates, and returning this pending owner grants neither Use nor ACK.
pub async fn reopen_initial_publication<'p, B: cwst::backend::Backend>(
    authentication: cfyr::passkeys::Authentication,
    mut initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    backend: B,
    clock: &mut impl Clock,
) -> Result<
    (
        cvlt::InitialCreation<B>,
        cfyr::membership::InitialCreationLease<'p, Transport>,
    ),
    cvlt::InitialError,
> {
    let (credential, vault) = authentication.into_parts();
    let id = credential.credential_id().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    let cfyr::passkeys::VaultOutcome::Ready(unlock) = vault else {
        return Err(refused());
    };
    reopen_initial_publication_opened(&id, Opening::Unlock(unlock), initial, backend, clock).await
}

/// The PRF of a reopening: a fresh assertion's unlock, or an opening the device already holds
/// (C7: the restart's one assertion logged in and unlocked; its opening reopens here).
pub enum Opening {
    Unlock(cfyr::passkeys::UnlockSecret),
    Opened(cvlt::PreparedOpen),
}

/// [`reopen_initial_publication`] from an assertion already split: `id` is its credential id
/// (the credential went to the login), `opening` its PRF. The same checks apply: the lease's
/// credential, this scope, this commitment.
pub async fn reopen_initial_publication_opened<'p, B: cwst::backend::Backend>(
    id: &[u8],
    opening: Opening,
    mut initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    backend: B,
    clock: &mut impl Clock,
) -> Result<
    (
        cvlt::InitialCreation<B>,
        cfyr::membership::InitialCreationLease<'p, Transport>,
    ),
    cvlt::InitialError,
> {
    if id
        != initial.credential_id().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused());
    }
    let mut clock = SharedClock::new(clock);
    let mut failed = false;
    let scope = initial
        .with_current(
            || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            },
            |current| current.community().to_owned(),
        )
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock));
    }
    let opening = match opening {
        Opening::Unlock(unlock) => {
            cvlt::PreparedOpen::new(unlock, &scope).map_err(cvlt::InitialError::Open)?
        }
        // An opening of another scope opens another vault: the reopen below finds nothing.
        Opening::Opened(opening) => opening,
    };
    let creation = opening.reopen_initial(backend).await?;
    if creation.enrollment_commitment()?
        != initial.seed().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused());
    }
    initial
        .check(|| {
            clock.now().unwrap_or_else(|_| {
                failed = true;
                u64::MAX
            })
        })
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock));
    }
    Ok((creation, initial))
}

/// The device-key twin of [`reopen_initial_publication`]: a device-key member restarted
/// during its first publication reopens its activated creation from the community opening
/// (the wallet unlock derives it; no passkey). Only under the device lease of the opening's
/// own device key and only for the commitment that lease holds; missing data never creates.
pub async fn reopen_device_initial_publication<'p, B: cwst::backend::Backend>(
    opening: cvlt::PreparedOpen,
    mut initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    backend: B,
    clock: &mut impl Clock,
) -> Result<
    (
        cvlt::InitialCreation<B>,
        cfyr::membership::InitialCreationLease<'p, Transport>,
    ),
    cvlt::InitialError,
> {
    let device = opening.device().map_err(cvlt::InitialError::Open)?;
    if initial.credential_id().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })? != device.value()
    {
        return Err(refused());
    }
    let creation = opening.reopen_initial(backend).await?;
    if creation.enrollment_commitment()?
        != initial.seed().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused());
    }
    let mut clock = SharedClock::new(clock);
    let mut failed = false;
    initial
        .check(|| {
            clock.now().unwrap_or_else(|_| {
                failed = true;
                u64::MAX
            })
        })
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock));
    }
    Ok((creation, initial))
}

/// Obtain the original dedicated receipt assertion from the maintained Passkeys
/// owner, retain all immutable publication inputs in the actual encrypted Store,
/// then bind that exact commitment through the original same-key server CAS.
/// There is no generic signer, replacement root, or unfinished-intent renewal.
pub async fn prepare_initial_publication<
    'p,
    B: cwst::backend::Backend,
    A: cfyr::passkeys::Authenticator,
>(
    creation: cvlt::InitialCreation<B>,
    mut initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    passkeys: &mut cfyr::passkeys::Client<A>,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<
    (
        cvlt::InitialCreation<B>,
        cfyr::membership::InitialCreationLease<'p, Transport>,
    ),
    InitialPublicationError,
> {
    let mut clock = SharedClock::new(clock);
    if creation.enrollment_commitment()?
        != initial.seed().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused().into());
    }
    let certificate = initial
        .certificate_bytes()
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .to_vec();
    let member = initial
        .observation()
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .member
        .clone();
    let challenge = creation
        .receipt()
        .passkey_challenge()
        .map_err(cvlt::InitialError::Keys)?;
    let now = clock.now().map_err(cvlt::InitialError::Keys)?;
    let mut failed = false;
    let options = initial
        .with_current(
            || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            },
            |current| {
                let certificate = current
                    .passkey_certificate(&certificate, &member, now)
                    .map_err(|__cause| {
                        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                    })?;
                serde_json::to_value(certificate.request(challenge, now).map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                })?)
                .map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                })
            },
        )
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })??;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock).into());
    }
    let (public, unused_unlock) = passkeys
        .sign_in(options)
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .into_parts();
    drop(unused_unlock);
    // Parse only through the original secret-rejecting Keyhole response codec;
    // it alone decodes the original WebAuthn signed byte fields.
    if serde_json::to_vec(public.as_json())
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .len()
        > cvlt::MAX_LINEAGE_EVIDENCE_BYTES
    {
        return Err(refused().into());
    }
    let public: ckyh::PublicKeyCredential =
        serde_json::from_value(public.into_json()).map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?;
    let assertion = ckyh::lineage::Assertion {
        credential_id: public.raw_id.to_vec(),
        client_data_json: public.response.client_data_json.to_vec(),
        authenticator_data: public.response.authenticator_data.to_vec(),
        signature: public.response.signature.to_vec(),
        user_handle: public
            .response
            .user_handle
            .as_ref()
            .map(|value| value.to_vec()),
    };
    let now = clock.now().map_err(cvlt::InitialError::Keys)?;
    let evidence = initial
        .with_current(
            || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            },
            |current| {
                let (_, author) = creation
                    .receipt()
                    .attested_lineage()
                    .map_err(cvlt::InitialError::Keys)?;
                if current.revocations().device_revoked(author.value()) {
                    return Err(refused());
                }
                cvlt::LineageEvidence::prepare(
                    current,
                    creation.receipt(),
                    &assertion,
                    &certificate,
                    &member,
                    now,
                )
                .map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                })
            },
        )
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })??;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock).into());
    }
    let expires = initial.expires().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    let creation = creation
        .prepare(&evidence, expires, &mut clock, entropy)
        .await?;
    let publication = creation.publication_commitment()?;
    let initial = initial
        .bind_publication(publication, || {
            clock.now().unwrap_or_else(|_| {
                failed = true;
                u64::MAX
            })
        })
        .await
        .map_err(InitialPublicationError::Foyer)?;
    if failed {
        return Err(InitialPublicationError::Foyer(cfyr::Error::Reconcile));
    }
    Ok((creation, initial))
}

/// The one-ceremony twin of [`prepare_initial_publication`] for the wallet scope (C4): no
/// passkey prompt. The wallet signs the birth statement for this creation's receipt
/// (`wallet_birth_genesis`, under the birth grant), the device checks it offline under the
/// current wallet Charter (it names this account, this creation's device key and its seed
/// commitment), retains the publication with that Birth evidence, and binds it through the
/// wallet's birth bind (the server verifies the same evidence before its CAS). `initial` is
/// the Door's own lease (current Charter, member, deadline); `wallet` a lease of the wallet
/// companion, the same session family. Returns the Prepared creation; the caller retains it
/// under a fresh lease.
pub async fn prepare_birth_publication<B: cwst::backend::Backend>(
    creation: cvlt::InitialCreation<B>,
    mut initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    mut wallet: cfyr::membership::GlobalWalletLease<Transport>,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::InitialCreation<B>, InitialPublicationError> {
    let mut clock = SharedClock::new(clock);
    let seed = initial.seed().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    if creation.enrollment_commitment()? != seed {
        return Err(refused().into());
    }
    let member = initial
        .observation()
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .member
        .clone();
    if wallet.user().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })? != member
    {
        return Err(refused().into());
    }
    let digest = creation
        .receipt()
        .passkey_challenge()
        .map_err(cvlt::InitialError::Keys)?;
    let mut failed = false;
    let (statement, at) = wallet
        .birth_genesis(digest, || {
            clock.now().unwrap_or_else(|_| {
                failed = true;
                u64::MAX
            })
        })
        .await
        .map_err(InitialPublicationError::Foyer)?
        .into_parts();
    if failed {
        return Err(InitialPublicationError::Foyer(cfyr::Error::Reconcile));
    }
    let evidence = cchr::BirthGenesisEvidence::new(creation.receipt().clone(), statement, at);
    let evidence_bytes = evidence.to_bytes().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    let expires = initial.expires().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    let (_, author) = creation
        .receipt()
        .attested_lineage()
        .map_err(cvlt::InitialError::Keys)?;
    let device = *author.value();
    let now = clock.now().map_err(cvlt::InitialError::Keys)?;
    let prepared = initial
        .with_current(
            || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            },
            |current| {
                if current.revocations().device_revoked(&device) {
                    return Err(refused());
                }
                let verified = cchr::verify_birth_genesis(
                    current.key_ring(),
                    &evidence,
                    &cchr::wallet_fingerprint(None),
                    &member,
                    now,
                )
                .map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                })?;
                if verified.statement().device() != &device
                    || verified.statement().commitment() != &seed
                {
                    return Err(refused());
                }
                cvlt::LineageEvidence::prepare_birth(current, evidence, &member, now).map_err(
                    |__cause| {
                        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                    },
                )
            },
        )
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })??;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock).into());
    }
    // The Door's lease is not held across the wallet's bind; the bind is its own CAS over the
    // same seed and the server verifies the same evidence first.
    drop(initial);
    let creation = creation
        .prepare(&prepared, expires, &mut clock, entropy)
        .await?;
    let publication = creation.publication_commitment()?;
    drop(
        wallet
            .bind_birth_creation(seed, publication, evidence_bytes, || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            })
            .await
            .map_err(InitialPublicationError::Foyer)?,
    );
    if failed {
        return Err(InitialPublicationError::Foyer(cfyr::Error::Reconcile));
    }
    Ok(creation)
}

/// The device-key twin of [`prepare_initial_publication`]: the genesis evidence is the
/// presentation of the `lineage_genesis` slot of the join's stamp (no passkey prompt), and
/// the bind carries it so the server checks it before its CAS. `initial` must be the device
/// lease whose key attested the receipt; `stamps` is the wallet's trust
/// (`GlobalWalletLease::stamp_trust`); `salt` the genesis slot's derived salt.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_device_initial_publication<'p, B, WB, WC, WE, WA, WR>(
    creation: cvlt::InitialCreation<B>,
    mut initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    wallet: &mut super::super::passport::GlobalPassport<WB, WC, WE, WA, WR>,
    stamps: &cvlt::StampTrust,
    salt: [u8; 32],
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<
    (
        cvlt::InitialCreation<B>,
        cfyr::membership::InitialCreationLease<'p, Transport>,
    ),
    InitialPublicationError,
>
where
    B: cwst::backend::Backend,
    WB: cwst::backend::Backend,
    WC: Clock,
    WE: ckmg::Entropy,
    WA: ckmg::Authority,
    WR: cvlt::Records,
{
    let mut clock = SharedClock::new(clock);
    if creation.enrollment_commitment()?
        != initial.seed().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused().into());
    }
    let (_, author) = creation
        .receipt()
        .attested_lineage()
        .map_err(cvlt::InitialError::Keys)?;
    // Only the device lease of the key that attested the receipt.
    if initial.credential_id().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })? != author.value()
    {
        return Err(refused().into());
    }
    let member = initial
        .observation()
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .member
        .clone();
    let at = creation.genesis_at()?;
    let action = cvlt::lineage_genesis_action(creation.receipt(), salt, at).map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    let mut failed = false;
    let scope = initial
        .with_current(
            || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            },
            |current| {
                cvlt::lineage_stamp_scope(current).map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                })
            },
        )
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })??;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock).into());
    }
    // Presented at the genesis time, not now: a restart after the stamp's cohort ended
    // re-presents the same genesis (the server re-confirms only that recorded digest).
    let presentation = wallet
        .with_global_passport(|holder| {
            holder.present_stamp(&mut cwlt::passport::rand::rngs::OsRng, &scope, &action, at)
        })
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?;
    let now = clock.now().map_err(cvlt::InitialError::Keys)?;
    let evidence = initial
        .with_current(
            || {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            },
            |current| {
                if current.revocations().device_revoked(author.value()) {
                    return Err(refused());
                }
                cvlt::LineageEvidence::prepare_stamp(
                    current,
                    stamps,
                    creation.receipt(),
                    &presentation,
                    salt,
                    at,
                    &member,
                    now,
                )
                .map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
                })
            },
        )
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })??;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock).into());
    }
    // The bind carries exactly the published genesis evidence bytes.
    let bound =
        cvlt::GenesisStampEvidence::new(creation.receipt().clone(), &presentation, salt, at)
            .to_bytes()
            .map_err(|__cause| {
                crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
            })?;
    let expires = initial.expires().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })?;
    let creation = creation
        .prepare(&evidence, expires, &mut clock, entropy)
        .await?;
    let publication = creation.publication_commitment()?;
    let initial = initial
        .bind_publication_with_evidence(publication, &bound, || {
            clock.now().unwrap_or_else(|_| {
                failed = true;
                u64::MAX
            })
        })
        .await
        .map_err(InitialPublicationError::Foyer)?;
    if failed {
        return Err(InitialPublicationError::Foyer(cfyr::Error::Reconcile));
    }
    Ok((creation, initial))
}

struct Completion<'p, C> {
    initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    clock: C,
    receipt: ckmg::Receipt,
    intent: ckmg::CompletionIntent,
    location: ckmg::Locator,
    sealed_digest: [u8; 32],
    publication: [u8; 32],
    /// The wallet's stamp trust on the device-key path (genesis evidence by stamp); None on
    /// the passkey path, where stamp evidence refuses.
    stamps: Option<cvlt::StampTrust>,
    closed: bool,
}

/// Verify `evidence` for `member` under `current`: stamp evidence only with the wallet's stamp
/// trust. The authority reference it proves is the passkey credential, or for stamp evidence
/// the device key that attested the receipt (the device lease's credential).
fn verified_reference<'a>(
    evidence: &'a cvlt::LineageEvidence,
    stamps: Option<&cvlt::StampTrust>,
    current: &'a cchr::VerifiedCharter,
    member: &str,
    now: u64,
) -> Result<(cvlt::VerifiedLineageObservation<'a>, Vec<u8>), Error> {
    let observed = match stamps {
        Some(stamps) => evidence.verify_with_stamps(current, stamps, member, now),
        None => evidence.verify(current, member, now),
    }
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "Error::Unauthorized",
            Error::Unauthorized,
            &__cause,
        )
    })?;
    let reference = if evidence.is_stamp() {
        observed
            .author(now)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .value()
            .to_vec()
    } else {
        observed
            .credential_id(now)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .to_vec()
    };
    Ok((observed, reference))
}
fn same_intent(a: &ckmg::CompletionIntent, b: &ckmg::CompletionIntent) -> bool {
    a.outer_generation == b.outer_generation
        && a.outer_digest == b.outer_digest
        && a.inner_version == b.inner_version
        && a.inner_operation == b.inner_operation
        && a.inner_digest == b.inner_digest
        && a.nonce == b.nonce
        && a.packed_evidence == b.packed_evidence
        && a.prepared_at == b.prepared_at
        && a.expires == b.expires
}
impl<C: Clock> Completion<'_, C> {
    fn current(&mut self, request: ckmg::CompletionAuthorization<'_>) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        if request.receipt != &self.receipt
            || request.location != &self.location
            || request.sealed_digest != &self.sealed_digest
            || !same_intent(request.intent, &self.intent)
            || request.authority_reference
                != self.initial.credential_id().map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Unauthorized",
                        Error::Unauthorized,
                        &__cause,
                    )
                })?
            || self.initial.publication().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })? != Some(self.publication)
        {
            return Err(Error::Unauthorized);
        }
        let commitment = request.receipt.initial_publication_commitment(
            &request.intent.nonce,
            &request.intent.packed_evidence,
            request.intent.prepared_at,
            request.intent.expires,
        )?;
        if commitment != self.publication {
            return Err(Error::Unauthorized);
        }
        let evidence = cvlt::LineageEvidence::from_packed(&request.intent.packed_evidence)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?;
        let (lineage, author) = request.receipt.attested_lineage()?;
        let observation = self.initial.observation().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        if observation.member != lineage.binding.member()
            || !observation.device_keys.contains(author.value())
        {
            return Err(Error::Unauthorized);
        }
        let now = self.clock.now()?;
        if now < request.now.max(request.intent.prepared_at) || now >= request.intent.expires {
            return Err(Error::Clock);
        }
        let mut failed = false;
        self.initial
            .with_current(
                || {
                    self.clock.now().unwrap_or_else(|_| {
                        failed = true;
                        u64::MAX
                    })
                },
                |current| {
                    if current.revocations().device_revoked(author.value()) {
                        return Err(Error::Revoked);
                    }
                    let (observed, reference) = verified_reference(
                        &evidence,
                        self.stamps.as_ref(),
                        current,
                        lineage.binding.member(),
                        now,
                    )?;
                    if observed.lineage(now).map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "Error::Unauthorized",
                            Error::Unauthorized,
                            &__cause,
                        )
                    })? != lineage
                        || observed.author(now).map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "Error::Unauthorized",
                                Error::Unauthorized,
                                &__cause,
                            )
                        })? != author
                        || reference != request.authority_reference
                    {
                        return Err(Error::Unauthorized);
                    }
                    Ok(())
                },
            )
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })??;
        if failed {
            return Err(Error::Clock);
        }
        let completed = self.initial.checked_at().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        if completed < now || completed >= request.intent.expires {
            return Err(Error::Clock);
        }
        self.closed = false;
        Ok(completed)
    }
}
impl<C: Clock> ckmg::Authority for Completion<'_, C> {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
    async fn check_completion(
        &mut self,
        request: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.current(request)
    }
    fn check_completion_current(
        &mut self,
        request: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.current(request)
    }
}

/// Complete only this actual Prepared checkpoint under a fresh original same-key
/// seed/publication lease. Every generation, digest, receipt and immutable field
/// is captured from the authenticated owner and compared again before signing.
pub async fn retain_initial_publication<B: cwst::backend::Backend>(
    creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    clock: &mut impl Clock,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    retain_publication(creation, initial, None, clock).await
}

/// [`retain_initial_publication`] of a device-key member: its genesis evidence by stamp is
/// verified with the wallet's stamp trust, and the device key is its authority reference.
pub async fn retain_device_initial_publication<B: cwst::backend::Backend>(
    creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    stamps: &cvlt::StampTrust,
    clock: &mut impl Clock,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    retain_publication(creation, initial, Some(stamps.clone()), clock).await
}

async fn retain_publication<B: cwst::backend::Backend>(
    creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    stamps: Option<cvlt::StampTrust>,
    clock: &mut impl Clock,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    if creation.enrollment_commitment()?
        != initial.seed().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused());
    }
    let publication = creation.publication_commitment()?;
    if initial.publication().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })? != Some(publication)
    {
        return Err(refused());
    }
    let (intent, location, sealed_digest) = creation.completion_binding()?;
    let mut clock = SharedClock::new(clock);
    let mut authority = Completion {
        initial,
        clock: clock.clone(),
        receipt: creation.receipt().clone(),
        intent,
        location,
        sealed_digest,
        publication,
        stamps,
        closed: false,
    };
    creation.retain(&mut clock, &mut authority).await
}

// This private composition exists only for the actual first-lineage witness and
// original Keys acknowledgment. Each ordinary Use performs original HTTPS reads
// before and after a fresh authenticated network read; no earlier result grants it.
struct AcknowledgmentAuthority<'p, C, R: cdht::runtime::Backend> {
    completion: Completion<'p, C>,
    records: cvlt::LineageRecords<R>,
    closed: bool,
}
impl<C: Clock, R: cdht::runtime::Backend> ckmg::Authority for AcknowledgmentAuthority<'_, C, R> {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        let (lineage, author) = self.completion.receipt.attested_lineage()?;
        if request.action != Action::Use
            || request.binding != &lineage.binding
            || request.root != Some(lineage.root)
            || request.device != author
            || request.epoch != lineage.epoch
            || request.target.is_some()
            || request.signing.is_some()
            || request
                .statement
                .is_some_and(|digest| lineage.digest().ok() != Some(digest))
        {
            return Err(Error::Unauthorized);
        }
        let mut failed = false;
        let clock = &mut self.completion.clock;
        let initial = &mut self.completion.initial;
        initial
            .refresh(|| {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            })
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?;
        if failed {
            return Err(Error::Clock);
        }
        let read = self.records.read().await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })?;
        initial
            .refresh(|| {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            })
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?;
        if failed {
            return Err(Error::Clock);
        }
        let now = clock.now()?;
        if now < request.now || now >= self.completion.intent.expires {
            return Err(Error::Clock);
        }
        let observation = initial.observation().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        if observation.member != lineage.binding.member()
            || !observation.device_keys.contains(author.value())
            || initial.publication().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })? != Some(self.completion.publication)
        {
            return Err(Error::Unauthorized);
        }
        let original = cvlt::LineageEvidence::from_packed(&self.completion.intent.packed_evidence)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .to_bytes()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?;
        let credential = initial
            .credential_id()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .to_vec();
        initial
            .with_current(
                || {
                    clock.now().unwrap_or_else(|_| {
                        failed = true;
                        u64::MAX
                    })
                },
                |current| {
                    if current.revocations().device_revoked(author.value())
                        || read.evidence().len() != 1
                    {
                        return Err(Error::Unauthorized);
                    }
                    let evidence = &read.evidence()[0];
                    if evidence.to_bytes().map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "Error::Unauthorized",
                            Error::Unauthorized,
                            &__cause,
                        )
                    })? != original
                    {
                        return Err(Error::Unauthorized);
                    }
                    let (actual, reference) = verified_reference(
                        evidence,
                        self.completion.stamps.as_ref(),
                        current,
                        lineage.binding.member(),
                        now,
                    )?;
                    if actual.lineage(now).map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "Error::Unauthorized",
                            Error::Unauthorized,
                            &__cause,
                        )
                    })? != lineage
                        || actual.author(now).map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "Error::Unauthorized",
                                Error::Unauthorized,
                                &__cause,
                            )
                        })? != author
                        || reference != credential
                    {
                        return Err(Error::Unauthorized);
                    }
                    Ok(())
                },
            )
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })??;
        if failed {
            return Err(Error::Clock);
        }
        if initial.checked_at().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })? >= self.completion.intent.expires
        {
            return Err(Error::Expired);
        }
        self.closed = false;
        Ok(())
    }
    async fn check_completion(
        &mut self,
        request: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.completion.current(request)
    }
    fn check_completion_current(
        &mut self,
        request: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.completion.current(request)
    }
}

/// Acknowledge only the original first-lineage consensus witness and exact
/// server-bound creation. Dedicated completion and every normal Keys Use retain
/// their separate real checks. The result is still an outer pending lifecycle;
/// recovery publication, forced selection and ordinary reopening remain required.
/// Production Tor callers must obtain `network` from `Network::initial_records`
/// before moving `initial`, so transport never re-locks its held Foyer session.
pub async fn acknowledge_initial_publication<B: cwst::backend::Backend, N: cdht::Network>(
    read: cvlt::InitialLineageRead<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    acknowledge_publication(read, initial, network, None, clock, entropy).await
}

/// [`acknowledge_initial_publication`] of a device-key member: the published genesis
/// evidence by stamp is verified with the wallet's stamp trust.
pub async fn acknowledge_device_initial_publication<B: cwst::backend::Backend, N: cdht::Network>(
    read: cvlt::InitialLineageRead<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
    stamps: &cvlt::StampTrust,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    acknowledge_publication(read, initial, network, Some(stamps.clone()), clock, entropy).await
}

async fn acknowledge_publication<B: cwst::backend::Backend, N: cdht::Network>(
    read: cvlt::InitialLineageRead<B>,
    mut initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
    stamps: Option<cvlt::StampTrust>,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    if read.enrollment_commitment()?
        != initial.seed().map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?
    {
        return Err(refused());
    }
    let publication = read.publication_commitment()?;
    if initial.publication().map_err(|__cause| {
        crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
    })? != Some(publication)
    {
        return Err(refused());
    }
    let mut clock = SharedClock::new(clock);
    let mut failed = false;
    initial
        .refresh(|| {
            clock.now().unwrap_or_else(|_| {
                failed = true;
                u64::MAX
            })
        })
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "refused", refused(), &__cause)
        })?;
    if failed {
        return Err(cvlt::InitialError::Keys(Error::Clock));
    }
    let (intent, location, sealed_digest) = read.completion_binding()?;
    let mut completion = Completion {
        initial,
        clock: clock.clone(),
        receipt: read.receipt().clone(),
        intent,
        location,
        sealed_digest,
        publication,
        stamps,
        closed: false,
    };
    let acknowledgment = read
        .prepare_acknowledgment(&mut clock, &mut completion)
        .await?;
    let reader = acknowledgment.lineage_reader()?;
    let backend = cvlt::TorLineageRecord::initial_lineage(network, reader)
        .await
        .map_err(cvlt::InitialError::Publication)?;
    let record = cdht::runtime::Record::new(backend).map_err(cvlt::InitialError::Publication)?;
    let records = cvlt::LineageRecords::new(vec![record]).map_err(cvlt::InitialError::Records)?;
    let mut authority = AcknowledgmentAuthority {
        completion,
        records,
        closed: false,
    };
    acknowledgment
        .acknowledge(&mut clock, entropy, &mut authority)
        .await
}
