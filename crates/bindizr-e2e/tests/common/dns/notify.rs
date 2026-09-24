//! A stand-in secondary that receives NOTIFY, records how each request was
//! signed, and answers as RFC 1996 asks, signed when the request was.

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
};

use domain::{
    base::{Message, MessageBuilder, Rtype, ToName, iana::Rcode},
    rdata::tsig::Time48,
    tsig::{Key, ServerTransaction},
};

use crate::common::dns::nsupdate::SigningKey;

/// One NOTIFY as the fake secondary saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceivedNotify {
    pub(crate) zone: String,
    /// The request carried a TSIG record.
    pub(crate) signed: bool,
    /// The TSIG verified under the fake's key; a signature under another key
    /// is answered with the TSIG error instead.
    pub(crate) verified: bool,
}

pub(crate) struct FakeSecondary {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<ReceivedNotify>>>,
}

impl FakeSecondary {
    /// Start on an ephemeral port; with `key`, a signed NOTIFY is verified
    /// under it and answered signed.
    pub(crate) fn start(key: Option<&SigningKey>) -> Self {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("failed to bind the fake secondary");
        let addr = socket
            .local_addr()
            .expect("failed to read the fake secondary's port");
        let key: Option<Arc<Key>> =
            key.map(|key| Arc::new(key.to_tsig_key().expect("the notify key converts")));
        let received: Arc<Mutex<Vec<ReceivedNotify>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&received);

        thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                    return;
                };
                let Ok(mut request) = Message::from_octets(buf[..len].to_vec()) else {
                    continue;
                };
                let Ok(question) = request.sole_question() else {
                    continue;
                };
                let zone = question.qname().to_name::<Vec<u8>>().to_string();
                let signed = request
                    .additional()
                    .map(|section| {
                        section
                            .flatten()
                            .any(|record| record.rtype() == Rtype::TSIG)
                    })
                    .unwrap_or(false);

                // With a key, the signature decides the answer.
                let mut signer = None;
                if let Some(key) = &key {
                    match ServerTransaction::request(key, &mut request, Time48::now()) {
                        Ok(context) => signer = context,
                        Err(error) => {
                            seen.lock().expect("received lock").push(ReceivedNotify {
                                zone,
                                signed,
                                verified: false,
                            });
                            if let Ok(response) =
                                error.build_message(&request, MessageBuilder::new_vec())
                            {
                                let _ = socket.send_to(&response.finish(), peer);
                            }
                            continue;
                        }
                    }
                }
                seen.lock().expect("received lock").push(ReceivedNotify {
                    zone,
                    signed,
                    verified: signer.is_some(),
                });

                let mut answer = MessageBuilder::new_vec()
                    .start_answer(&request, Rcode::NOERROR)
                    .expect("start the answer")
                    .additional();
                if let Some(signer) = signer {
                    signer
                        .answer(&mut answer, Time48::now())
                        .expect("sign the answer");
                }
                let _ = socket.send_to(&answer.finish(), peer);
            }
        });

        Self { addr, received }
    }

    /// The `host:port` to register the fake as a secondary under.
    pub(crate) fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Every NOTIFY received so far, in order.
    pub(crate) fn received(&self) -> Vec<ReceivedNotify> {
        self.received.lock().expect("received lock").clone()
    }
}
