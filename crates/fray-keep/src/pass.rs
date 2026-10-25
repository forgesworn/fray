//! The rule for believing a return pass.
//!
//! After a player is let into a room on a Keep by room code, the Keep can hand
//! the player a pass: the way back in, as a host key and a secret, to save in
//! My Keeps. A pass must only be believed from the Keep it names, or any room
//! could fill the list with Keeps it does not run. How a pass travels (the
//! message, the queue that holds it) is each game's own; this is only the
//! rule.

/// Believe a pass naming `pass_host_key` only when the key the transport
/// proved for this link (the one the host's signed welcome was made with) is
/// known and is exactly that key. With no proven key, nothing matches and the
/// pass is dropped.
pub fn accept_pass(proven_host_key: Option<[u8; 32]>, pass_host_key: &[u8; 32]) -> bool {
    proven_host_key.as_ref() == Some(pass_host_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_is_believed_only_from_the_proven_host() {
        let host = [7u8; 32];
        assert!(accept_pass(Some(host), &host));
        assert!(!accept_pass(Some(host), &[8u8; 32]), "another host's key");
        assert!(!accept_pass(None, &host), "no proven key: dropped");
        assert!(!accept_pass(None, &[0u8; 32]));
        let mut near = host;
        near[31] ^= 1;
        assert!(!accept_pass(Some(host), &near), "one bit off");
    }
}
