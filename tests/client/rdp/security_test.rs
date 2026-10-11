//! The RDP client's checks that need no server: which security protocols it offers (NLA alone
//! unless told otherwise), when the security the server selected may carry the password, and
//! which granted desktop sizes it will allocate a framebuffer for. The real-server suite covers
//! the sessions themselves; these pin the decisions a hostile server would aim at.
use netget::client::rdp::{
    actions, check_granted_size, check_selected_security, security_offer, RdpClientProtocol,
};
use netget::llm::actions::protocol_trait::Protocol;
use serde_json::json;

#[test]
fn the_default_offers_nla_only() {
    assert_eq!(actions::DEFAULT_SECURITY, "nla");
    assert_eq!(security_offer(None).unwrap(), (false, true), "(tls, nla)");
    assert_eq!(security_offer(Some("nla")).unwrap(), (false, true));
    assert_eq!(security_offer(Some("tls")).unwrap(), (true, false));
    assert_eq!(security_offer(Some("any")).unwrap(), (true, true));
    assert!(security_offer(Some("rdp")).is_err());
    // The declared default is the one the code falls back to.
    let params = RdpClientProtocol.get_startup_parameters();
    let security = params
        .iter()
        .find(|p| p.name == "security")
        .expect("a security parameter");
    assert_eq!(security.default, Some(json!(actions::DEFAULT_SECURITY)));
}

#[test]
fn a_password_crosses_tls_only_security_only_when_tls_was_asked_for() {
    check_selected_security("nla", "nla", true).unwrap();
    check_selected_security("any", "nla", true).unwrap();
    check_selected_security("tls", "tls", true).unwrap();
    // No password, nothing to hand over: TLS reaches the server's own login screen.
    check_selected_security("any", "tls", false).unwrap();
    let err = check_selected_security("any", "tls", true).unwrap_err();
    assert!(err.to_string().contains("set security to tls"), "{err}");
    assert!(check_selected_security("nla", "tls", true).is_err());
}

#[test]
fn granted_desktop_sizes_are_bounded() {
    check_granted_size(1024, 768).unwrap();
    check_granted_size(1, 1).unwrap();
    check_granted_size(actions::MAX_SIDE, actions::MAX_SIDE).unwrap();
    for (w, h) in [
        (actions::MAX_SIDE + 1, 768),
        (1024, actions::MAX_SIDE + 1),
        (u16::MAX, u16::MAX),
        (0, 768),
        (1024, 0),
    ] {
        let err = check_granted_size(w, h).unwrap_err();
        assert!(err.to_string().contains(&format!("{w}x{h}")), "{err}");
    }
}
