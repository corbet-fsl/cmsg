//! Genuine member/garden/root-board fixtures, with explicit preexisting roles.
//! Register initialization below is test setup, not production first-role proof.
use super::*;
use cvld::api::{
    Bytes, Ceremony, CredentialResponse, GlobalPublic, PresentationChallenge, PresentationInput,
    RootBoardIssueChallenge, TrustFeed,
};

async fn anchor(service: &Running, host: &str, scope: &str) -> cpsd::AuthenticatedCommunity {
    let feed: TrustFeed = serde_json::from_value(
        client(service, host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(scope).unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    )
}

/// Move a founded or promoted member to its garden (admin host) session.
async fn garden_session(service: &Running, scope: &str, member: &mut Member) {
    let host = format!("api.admin.{scope}.example.test");
    member.session = login(
        service,
        &host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
}

/// Found `scope` for real: its first Root member prepares an original creation
/// recipient, the Global Root operator initializes the community through the
/// public action, and the member redeems the signed invitation with every
/// configured admission gate. No library hook or role setter is involved.
async fn found(
    wallet: &Running,
    operator: &Member,
    service: &Running,
    scope: &str,
    holder: &cpsd::OpaqueHolder,
    member: &Member,
    handle: &str,
) -> CredentialResponse {
    let host = format!("api.{scope}.example.test");
    let session = Some(member.session.as_str());
    let api = client(service, &host, session);
    api.call("handle_reserve", json!({"handle":handle}))
        .await
        .unwrap();
    let recipient = api
        .call(
            "community_creation_recipient",
            json!({"id":null,"expires_at":NOW + 300}),
        )
        .await
        .unwrap();
    let invitation = match client(wallet, ROOT, Some(&operator.session))
        .call(
            "community_creation_initialize",
            json!({"community":scope,"recipient":recipient["recipient"]}),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            // Test-side diagnosis only: the real HTTP-level refusal for this founding.
            eprintln!("founding {scope} refused: {error:?}");
            panic!("founding refused");
        }
    };
    let pseudonym = holder
        .pseudonym(&cpsd::CommunityId::new(scope).unwrap())
        .to_hex();
    api.call(
        "gate_voucher",
        voucher(scope, &pseudonym, handle, NOW + 172800),
    )
    .await
    .unwrap();
    let presentation = proof(service, scope, holder, session).await;
    let admitted: CredentialResponse = serde_json::from_value(
        client(service, &host, session)
            .call(
                "credential_issue",
                json!({
                    "presentation":presentation,"devices":[member.signing_key],
                    "creation":invitation["invitation"]
                }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(admitted.lobby.state, "admitted");
    admitted
}

async fn gates(
    service: &Running,
    host: &str,
    member: &Member,
    pseudonym: &str,
    scope: &str,
    handle: &str,
) {
    let session = client(service, host, Some(&member.session));
    session
        .call("handle_reserve", json!({"handle":handle}))
        .await
        .unwrap();
    session
        .call(
            "gate_voucher",
            voucher(scope, pseudonym, handle, NOW + 172800),
        )
        .await
        .unwrap();
}

/// An ordinary admitted member promoted by the founded Root under its garden session.
pub async fn admin(wallet: &Running, source: &Running, root: &Member) -> Member {
    let (_, passport, _) = wallet_passport(wallet).await;
    let host = "api.alpha.example.test";
    let mut member = enrol_community(source, host, &passport).await;
    let pseudonym = passport
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    gates(source, host, &member, &pseudonym, "alpha", "fixture_admin").await;
    let admitted = issue_community(source, host, &member, &passport).await;
    assert_eq!(admitted.lobby.state, "admitted");
    client(
        source,
        "api.admin.alpha.example.test",
        Some(&root.session),
    )
    .call(
        "member_role_set",
        json!({"member":admitted.lobby.member_id,"role":"admin"}),
    )
    .await
    .unwrap();
    garden_session(source, "alpha", &mut member).await;
    member
}

async fn holder(wallet: &Running) -> cpsd::OpaqueHolder {
    let member = enrol(wallet, WALLET, None).await;
    let client = client(wallet, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed_and_sealing_key(
        &mut [81; 32],
        &mut [82; 32],
        b"cmsg-linked-root-fixture",
    )
    .unwrap();
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let request = holder
        .begin_issuance(&mut cpsd::rand::rngs::OsRng, &issuer, &challenge)
        .unwrap();
    let answer: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({
                    "challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),
                }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&answer.bytes).unwrap())
        .unwrap();
    holder
}

async fn proof(
    service: &Running,
    scope: &str,
    holder: &cpsd::OpaqueHolder,
    session: Option<&str>,
) -> PresentationInput {
    let host = format!("api.{scope}.example.test");
    let challenge: PresentationChallenge = serde_json::from_value(
        match client(service, &host, session)
            .call("presentation_challenge", json!({}))
            .await
        {
            Ok(value) => value,
            Err(error) => {
                let status = match session {
                    Some(token) => {
                        let response = reqwest::Client::new()
                            .post(format!("{}/v1/presentation_challenge", service.base))
                            .header("host", host.as_str())
                            .bearer_auth(token)
                            .json(&json!({}))
                            .send()
                            .await
                            .unwrap();
                        let code = response.status().as_u16();
                        format!("{code} {}", response.text().await.unwrap())
                    }
                    None => String::new(),
                };
                let feed = reqwest::Client::new()
                    .post(format!("{}/v1/trust_feed", service.base))
                    .header("host", host.as_str())
                    .json(&json!({}))
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap();
                let parsed: serde_json::Value = serde_json::from_str(&feed).unwrap();
                let shape: Vec<String> = parsed
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(key, value)| match value {
                        serde_json::Value::Array(items) => format!("{key}[{}]", items.len()),
                        serde_json::Value::Object(_) => format!("{key}{{}}"),
                        other => format!("{key}={other}"),
                    })
                    .collect();
                eprintln!(
                    "community clock {}; trust feed fields {}",
                    service.clock.0.load(std::sync::atomic::Ordering::SeqCst),
                    shape.join(" ")
                );
                eprintln!(
                    "presentation_challenge on {host} refused: {error:?}; session {}; http {status}",
                    session.is_some()
                );
                panic!("presentation challenge refused");
            }
        },
    )
    .unwrap();
    let anchor = anchor(service, &host, scope).await;
    let bytes = if scope == "root" {
        holder
            .present_root_board(
                &mut cpsd::rand::rngs::OsRng,
                &anchor,
                &challenge.request,
                NOW,
            )
            .unwrap()
            .to_bytes()
    } else {
        holder
            .present(
                &mut cpsd::rand::rngs::OsRng,
                &anchor,
                &challenge.request,
                NOW,
            )
            .unwrap()
            .to_bytes()
    };
    PresentationInput {
        challenge: challenge.challenge,
        proof: bytes,
    }
}

async fn root_member(
    wallet: &Running,
    operator: &Member,
    service: &Running,
    scope: &str,
    holder: &cpsd::OpaqueHolder,
    handle: &str,
) -> Member {
    let host = format!("api.{scope}.example.test");
    // Link before any member session exists: the link changes the target's state.
    wallet.door.link_community_creation(&service.door).await.unwrap();
    let presentation = proof(service, scope, holder, None).await;
    let ceremony: Ceremony = serde_json::from_value(
        client(service, &host, None)
            .call("register_begin", json!({"passport":presentation}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut member = finish_enrol(service, &host, ceremony).await;
    found(wallet, operator, service, scope, holder, &member, handle).await;
    garden_session(service, scope, &mut member).await;
    member
}

/// The community's first registration and Root: nothing else may register before it.
pub async fn found_source(
    wallet: &Running,
    operator: &Member,
    source: &Running,
) -> (cpsd::OpaqueHolder, Member) {
    let holder = holder(wallet).await;
    let member = root_member(
        wallet,
        operator,
        source,
        "alpha",
        &holder,
        "fixture_source_root",
    )
    .await;
    (holder, member)
}

pub async fn roots(
    wallet: &Running,
    operator: &Member,
    mut holder: cpsd::OpaqueHolder,
    source_member: Member,
    source: &Running,
    board: &Running,
) -> (Member, Member) {
    let garden = client(
        source,
        "api.admin.alpha.example.test",
        Some(&source_member.session),
    );
    let challenge: RootBoardIssueChallenge = serde_json::from_value(
        garden
            .call("root_board_issue_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let source_anchor = anchor(source, "api.alpha.example.test", "alpha").await;
    let root_anchor = anchor(board, "api.root.example.test", "root").await;
    let request = holder
        .begin_root_board_issuance(
            &mut cpsd::rand::rngs::OsRng,
            &root_anchor,
            &challenge.signed_context,
            &source_anchor,
            &challenge.signed_source_request,
            NOW,
        )
        .unwrap();
    let answer: Bytes = serde_json::from_value(
        garden
            .call(
                "root_board_issue_finish",
                json!({
                    "challenge":challenge.challenge,"proof":request.to_bytes(),
                }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_root_board_issuance(
            &cpsd::BlindRootBoardCredential::from_bytes(&answer.bytes).unwrap(),
        )
        .unwrap();
    let board_member = root_member(wallet, operator, board, "root", &holder, "fixture_board_root").await;
    (source_member, board_member)
}
