//! Custody model of voucher links: the issuer's and the newcomer's devices must
//! derive the same bond, and the record must survive an encode/decode round trip.
use super::*;

fn issued_with(token: &Token, secret: &IssuerSecret) -> Issued {
    Issued {
        id: token.id().as_str().into(),
        fragment: token.fragment().to_string(),
        key: to_hex(secret.as_bytes()),
        uses: 3,
        signoff: true,
        visible: true,
        created_at: 10,
        expires_at: 1000,
        pending: false,
        revoked: false,
        done: false,
    }
}

fn link() -> (Token, IssuerSecret) {
    Token::issue([7; 32], [9; 32], [5; 32]).unwrap()
}

#[test]
fn hex_round_trips_and_refuses_bad_input() {
    assert_eq!(to_hex(&[0, 15, 16, 255]), "000f10ff");
    assert_eq!(from_hex("000f10ff"), Some(vec![0, 15, 16, 255]));
    assert_eq!(from_hex("abc"), None);
    assert_eq!(from_hex("0G"), None);
    assert_eq!(from_hex("0F"), None);
}

#[test]
fn record_round_trips_and_a_foreign_version_is_refused() {
    let (token, secret) = link();
    let mut book = Book::decode(None).unwrap();
    book.add_issued(issued_with(&token, &secret)).unwrap();
    let bytes = book.encode().unwrap();
    assert_eq!(Book::decode(Some(&bytes)).unwrap(), book);
    assert_eq!(
        Book::decode(Some(b"{\"version\":9}")).err(),
        Some(ErrorCode::Unavailable)
    );
    assert_eq!(
        Book::decode(Some(b"nope")).err(),
        Some(ErrorCode::Unavailable)
    );
}

#[test]
fn a_link_is_added_once() {
    let (token, secret) = link();
    let mut book = Book::decode(None).unwrap();
    book.add_issued(issued_with(&token, &secret)).unwrap();
    assert_eq!(
        book.add_issued(issued_with(&token, &secret)),
        Err(ErrorCode::Capacity)
    );
}

#[test]
fn the_nonce_is_chosen_once_per_link() {
    let (token, _) = link();
    let text = token.fragment().to_string();
    let mut book = Book::decode(None).unwrap();
    let first = book.nonce_for(&text).unwrap();
    assert_eq!(book.nonce_for(&format!("#{text}")).unwrap(), first);
    let again = Book::decode(Some(&book.encode().unwrap())).unwrap();
    let mut again = again;
    assert_eq!(again.nonce_for(&text).unwrap(), first);
    assert_eq!(book.nonce_for("nonsense"), Err(ErrorCode::InvalidRequest));
}

#[test]
fn both_devices_derive_the_same_bond() {
    let (token, secret) = link();
    let mut issuer = Book::decode(None).unwrap();
    issuer.add_issued(issued_with(&token, &secret)).unwrap();
    // The newcomer's device parses the link text and seals a notice.
    let text = token.fragment().to_string();
    let mut newcomer = Book::decode(None).unwrap();
    let nonce = newcomer.nonce_for(&text).unwrap();
    let parsed = Token::parse(&text).unwrap();
    let notice = Notice {
        member: "member-1".into(),
        nonce,
        handle: Some("@new".into()),
    };
    let sealed = to_hex(&parsed.seal(&notice).unwrap());
    let vouchee_bond = parsed.bond("member-1", &nonce);
    newcomer.add_vouchee_bond(&text, &vouchee_bond).unwrap();

    let entries = vec![WireEntry {
        member: "member-1".into(),
        notice: sealed.clone(),
    }];
    let opened = issuer.absorb(token.id().as_str(), &entries).unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].member, "member-1");
    assert_eq!(opened[0].token_bond.as_bytes(), vouchee_bond.as_bytes());
    assert_eq!(newcomer.bonds.len(), 1);
    assert!(!newcomer.bonds[0].sponsor);

    // A notice that names another member than the community reports yields no bond.
    let liar = vec![WireEntry {
        member: "member-2".into(),
        notice: sealed,
    }];
    assert!(issuer
        .absorb(token.id().as_str(), &liar)
        .unwrap()
        .is_empty());
    // So does a notice that is not even hex.
    let junk = vec![WireEntry {
        member: "member-1".into(),
        notice: "zz".into(),
    }];
    assert!(issuer
        .absorb(token.id().as_str(), &junk)
        .unwrap()
        .is_empty());
    assert_eq!(
        issuer.absorb(&"0".repeat(64), &entries).err(),
        Some(ErrorCode::Refused)
    );
}

#[test]
fn a_bond_is_recorded_once_per_person() {
    let mut book = Book::decode(None).unwrap();
    let entry = BondEntry {
        sponsor: true,
        link: "l".into(),
        member: "m".into(),
        bond: "aa".into(),
        sponsor_id: String::new(),
    };
    assert!(book.add_bond(entry.clone()).unwrap());
    let mut second = entry;
    second.bond = "bb".into();
    assert!(!book.add_bond(second).unwrap());
    assert_eq!(book.bonds[0].bond, "aa");
}

#[test]
fn state_follows_revocation_expiry_and_uses() {
    let (token, secret) = link();
    let mut link = issued_with(&token, &secret);
    assert_eq!(state(&link, 0, 20), "open");
    assert_eq!(state(&link, 3, 20), "full");
    assert_eq!(state(&link, 0, 1000), "expired");
    link.revoked = true;
    assert_eq!(state(&link, 0, 20), "revoked");
    link.pending = true;
    assert_eq!(state(&link, 0, 20), "pending");
    assert_eq!(info(&link, 1, 2, 20).waiting, 2);
}

#[test]
fn an_exhausted_allowance_stops_only_open_links() {
    let (token, secret) = link();
    let mut book = Book::decode(None).unwrap();
    let open = issued_with(&token, &secret);
    let mut revoked = open.clone();
    revoked.id = "r".into();
    revoked.revoked = true;
    let mut pending = open.clone();
    pending.id = "p".into();
    pending.pending = true;
    book.issued = vec![open.clone(), revoked, pending];
    assert_eq!(exhausted(&book, Some(0), 20), vec![open.id.clone()]);
    assert!(exhausted(&book, Some(1), 20).is_empty());
    assert!(exhausted(&book, None, 20).is_empty());
    assert!(exhausted(&book, Some(0), 1000).is_empty());
}

#[test]
fn applicant_ids_split_into_link_and_member() {
    let link = "a".repeat(64);
    let id = applicant_id(&link, "member-1");
    assert_eq!(split_applicant(&id), Ok((link.as_str(), "member-1")));
    assert_eq!(split_applicant("nolink"), Err(ErrorCode::InvalidRequest));
    assert_eq!(
        split_applicant(&format!("{link}:")),
        Err(ErrorCode::InvalidRequest)
    );
    assert_eq!(split_applicant("short:m"), Err(ErrorCode::InvalidRequest));
}

#[test]
fn the_vouchee_keeps_the_sponsor_id_from_the_link_text_beside_the_bond() {
    let (token, _) = link();
    let mut book = Book::decode(None).unwrap();
    assert_eq!(book.vouchee_bond(), None);
    let bond = Bond::from_bytes([3; 32]);
    book.add_vouchee_bond(&token.fragment(), &bond).unwrap();
    assert_eq!(book.vouchee_bond(), Some(([5; 32], [3; 32])));
    // The issuer's own entries never count as a vouchee bond.
    let mut issuer = Book::decode(None).unwrap();
    issuer
        .add_bond(BondEntry {
            sponsor: true,
            link: "l".into(),
            member: "m".into(),
            bond: "aa".repeat(32),
            sponsor_id: String::new(),
        })
        .unwrap();
    assert_eq!(issuer.vouchee_bond(), None);
}
