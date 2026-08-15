//! Type-level trust calculus: receiving requires authentication.
//!
//! Run: `cargo run --example trust_session --features trust`
//!
//! `Session<Handshake, _>` has no `recv` method — receiving unauthenticated
//! data is a compile error, not a runtime check. After `authenticate`, the
//! session moves to the authenticated state and `recv` becomes available.
//! `TrustedConfig<C, Untrusted>` can only deserialize through the explicitly
//! named `deserialize_untrusted`; the plain `deserialize` name is reserved
//! for the authenticated state.

use rustbinary::{Authenticated, Handshake, Session, TrustedConfig, Untrusted, Verified, Verifier};

#[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
struct Order {
    id: u64,
    side: String,
    quantity: u64,
}

fn main() -> rustbinary::Result<()> {
    let codec = rustbinary::options().with_limit(1 << 16);

    // --- TrustedConfig: the state is in the type ---------------------------
    let unauthenticated = TrustedConfig::<rustbinary::Config, Untrusted>::unauthenticated(codec);
    let order = Order {
        id: 1,
        side: "buy".into(),
        quantity: 100,
    };
    let frame = unauthenticated.serialize(&order)?;
    // The only way to deserialize here is the explicitly named method.
    let same: Order = unauthenticated.deserialize_untrusted(&frame)?;
    assert_eq!(same, order);

    // The only transition to Authenticated demands a Verifier.
    let expected = frame.clone();
    let authenticated = unauthenticated.authenticate(Verifier::new(move |bytes| {
        if bytes == expected.as_slice() {
            Ok(())
        } else {
            Err(rustbinary::Error::Trust("frame not authenticated"))
        }
    }));
    // Now the plain `deserialize` name exists, and the result can be Verified.
    let decoded: Order = authenticated.deserialize(&frame)?;
    let verified: Verified<Order> = authenticated.deserialize_verified(&frame)?;
    assert_eq!(decoded, verified.into_inner());
    println!(
        "TrustedConfig: unauthenticated deserialize is explicit, verified deserialize is typed"
    );

    // --- Session: recv only exists after authentication --------------------
    let payload = codec.serialize(&order)?;
    let mut stream = Vec::new();
    stream.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    stream.extend_from_slice(&payload);

    let handshake = Session::new(codec, std::io::Cursor::new(stream));
    // `handshake.recv::<Order>()` would not compile: Session<Handshake, _>
    // has no recv. Authenticate first:
    let mut session = handshake.authenticate(Verifier::new(|_| Ok(())));
    let received: Verified<Order> = session.recv_verified()?;
    assert_eq!(received.into_inner(), order);
    println!("Session: Handshake -> Authenticated -> recv_verified OK");
    let _closed = session.close();
    println!("Session: closed (terminal state)");
    Ok(())
}

// Reference the markers so the docs stay accurate in the example.
#[allow(dead_code)]
fn _state_types() {
    let _ = (Handshake {}, Authenticated {}, Untrusted {});
}
