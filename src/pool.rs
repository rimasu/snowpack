use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedMutexGuard};

use crate::auth::SignedAuthHeader;
use crate::messages::{MessageRx, MessageTx};
use crate::noise::TransportPrivateKey;
use crate::sign::SignatureVerificationKey;
use crate::{ConnectionError, NodeId};

// ── Credentials ───────────────────────────────────────────────────────────────

/// Local node credentials required for the Noise handshake.
pub struct Credentials {
    pub private_key: TransportPrivateKey,
    pub auth_header: SignedAuthHeader,
    pub verification_key: SignatureVerificationKey,
}

// ── Connector ─────────────────────────────────────────────────────────────────

/// Opens a raw byte stream to a peer. The pool calls this when it needs to
/// (re)establish a connection; the Noise handshake is performed on top of the
/// returned stream.
///
/// The trait is generic so tests can substitute in-memory duplex streams.
pub trait Connector: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn connect(&self) -> impl Future<Output = Result<Self::Stream, ConnectionError>> + Send;
}

// ── TcpConnector ─────────────────────────────────────────────────────────────

/// A [`Connector`] that opens a plain TCP stream to a fixed `(hostname, port)`.
///
/// Suitable for most cluster deployments. For TLS or other transports, implement
/// [`Connector`] directly.
pub struct TcpConnector {
    pub hostname: String,
    pub port: u16,
}

impl Connector for TcpConnector {
    type Stream = tokio::net::TcpStream;
    fn connect(&self) -> impl Future<Output = Result<tokio::net::TcpStream, ConnectionError>> + Send {
        let addr = (self.hostname.clone(), self.port);
        async move {
            tokio::net::TcpStream::connect(addr)
                .await
                .map_err(ConnectionError::Io)
        }
    }
}

// ── Internal link state ───────────────────────────────────────────────────────

enum LinkState<C: Connector> {
    Connected {
        tx: MessageTx<WriteHalf<C::Stream>>,
        rx: MessageRx<ReadHalf<C::Stream>>,
    },
    Reconnecting,
}

struct PeerLink<C: Connector> {
    connector: C,
    target: NodeId,
    creds: Arc<Credentials>,
    state: Arc<AsyncMutex<LinkState<C>>>,
    connected: Arc<Notify>,
}

impl<C: Connector> PeerLink<C> {
    fn new(connector: C, target: NodeId, creds: Arc<Credentials>) -> Arc<Self> {
        let link = Arc::new(Self {
            connector,
            target,
            creds,
            state: Arc::new(AsyncMutex::new(LinkState::Reconnecting)),
            connected: Arc::new(Notify::new()),
        });
        tokio::spawn(reconnect_task(Arc::clone(&link)));
        link
    }
}

// ── Background reconnect task ─────────────────────────────────────────────────

async fn reconnect_task<C: Connector>(link: Arc<PeerLink<C>>) {
    let mut backoff = Duration::from_millis(50);
    loop {
        let t0 = std::time::Instant::now();
        let result = try_connect(&link).await;
        match result {
            Ok((tx, rx)) => {
                let elapsed = t0.elapsed().as_secs_f64();
                metrics::histogram!("snowpack.handshake.seconds").record(elapsed);
                metrics::counter!("snowpack.reconnect_total").increment(1);
                let mut state = link.state.lock().await;
                *state = LinkState::Connected { tx, rx };
                link.connected.notify_waiters();
                return;
            }
            Err(e) => {
                metrics::counter!("snowpack.connect_error_total").increment(1);
                tracing::warn!("snowpack: connect to peer failed: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn try_connect<C: Connector>(
    link: &PeerLink<C>,
) -> Result<(MessageTx<WriteHalf<C::Stream>>, MessageRx<ReadHalf<C::Stream>>), ConnectionError> {
    let stream = link.connector.connect().await?;
    let ((tx, rx), auth_details) = crate::connect(
        stream,
        &link.creds.private_key,
        &link.creds.auth_header,
        &link.creds.verification_key,
    )
    .await?;
    auth_details.check_node_id(link.target.clone())?;
    Ok((tx, rx))
}

// ── ConnectionPool ────────────────────────────────────────────────────────────

/// Maintains one authenticated Noise connection per peer, reconnecting in the
/// background whenever a link drops.
///
/// Generic over `C: Connector` so that tests can substitute a duplex-stream
/// connector without touching the network.
pub struct ConnectionPool<C: Connector> {
    creds: Arc<Credentials>,
    peers: Mutex<HashMap<NodeId, Arc<PeerLink<C>>>>,
}

impl<C: Connector> ConnectionPool<C> {
    pub fn new(creds: Arc<Credentials>) -> Self {
        Self {
            creds,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Return an [`Connection`] for `target`, creating one if needed.
    ///
    /// `make_connector` is only called on the first access for a given target.
    /// The background handshake starts immediately; the first few
    /// [`Connection::acquire`] calls may return [`NotReady`] until it
    /// completes.
    pub fn peer(&self, target: NodeId, make_connector: impl FnOnce() -> C) -> Connection<C> {
        let mut peers = self.peers.lock().unwrap();
        let link = peers
            .entry(target.clone())
            .or_insert_with(|| PeerLink::new(make_connector(), target, Arc::clone(&self.creds)));
        Connection { link: Arc::clone(link) }
    }
}

// ── Connection ───────────────────────────────────────────────────────────

/// A logical connection handle to one peer. Cheap to clone — all clones share
/// the same underlying connection and reconnect state.
pub struct Connection<C: Connector> {
    link: Arc<PeerLink<C>>,
}

impl<C: Connector> Clone for Connection<C> {
    fn clone(&self) -> Self {
        Self { link: Arc::clone(&self.link) }
    }
}

/// Returned by [`Connection::acquire`] when the link is currently
/// establishing (or re-establishing) a connection.
#[derive(Debug)]
pub struct NotReady;

impl<C: Connector> Connection<C> {
    /// Attempt to acquire exclusive access to the connection for one RPC
    /// exchange.
    ///
    /// Returns [`NotReady`] if the link is currently reconnecting. The caller
    /// should treat this as a transient error and retry after backing off;
    /// the background task will establish the connection in the meantime.
    ///
    /// The returned [`Guard`] holds the connection lock until dropped. Drop it
    /// without calling [`Guard::commit`] to signal that the Noise channel may
    /// be in an inconsistent state (e.g. because the enclosing future was
    /// cancelled mid-exchange); the pool will then reset and reconnect.
    pub async fn acquire(&self) -> Result<Guard<C>, NotReady> {
        let guard = Arc::clone(&self.link.state).lock_owned().await;
        match &*guard {
            LinkState::Connected { .. } => Ok(Guard {
                inner: guard,
                link: Arc::clone(&self.link),
                committed: false,
            }),
            LinkState::Reconnecting => Err(NotReady),
        }
    }

    /// Wait until the connection is established, or until `timeout` elapses.
    ///
    /// Returns `Ok(())` once the link is `Connected`. Returns `Err(NotReady)`
    /// if the timeout expires before the handshake completes — the caller can
    /// proceed anyway; subsequent RPCs will handle [`NotReady`] as normal.
    ///
    /// Registers for the connection notification *before* checking state so
    /// that a handshake completing between the check and the await is never
    /// missed.
    pub async fn wait_connected(&self, timeout: Duration) -> Result<(), NotReady> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.link.connected.notified();
            {
                let state = self.link.state.lock().await;
                if matches!(*state, LinkState::Connected { .. }) {
                    return Ok(());
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(NotReady);
            }
        }
    }
}

// ── Guard ─────────────────────────────────────────────────────────────────────

/// Exclusive access to the connection for one RPC exchange.
///
/// Call [`Guard::commit`] after a successful exchange to release the lock
/// cleanly. If the guard is dropped without committing (including via future
/// cancellation), the pool resets the Noise channel and reconnects.
pub struct Guard<C: Connector> {
    inner: OwnedMutexGuard<LinkState<C>>,
    link: Arc<PeerLink<C>>,
    committed: bool,
}

impl<C: Connector> Guard<C> {
    /// Borrow the send and receive halves of the Noise transport.
    #[allow(clippy::type_complexity)]
    pub fn transport(
        &mut self,
    ) -> (
        &mut MessageTx<WriteHalf<C::Stream>>,
        &mut MessageRx<ReadHalf<C::Stream>>,
    ) {
        match &mut *self.inner {
            LinkState::Connected { tx, rx } => (tx, rx),
            LinkState::Reconnecting => unreachable!("Guard only exists when Connected"),
        }
    }

    /// Mark the exchange as complete. The lock is released and the connection
    /// is returned to the pool in a clean state.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl<C: Connector> Drop for Guard<C> {
    fn drop(&mut self) {
        if !self.committed {
            // The Noise channel may be in an unknown state (e.g. the future
            // was cancelled mid-send). Reset the connection and start
            // reconnecting in the background.
            metrics::counter!("snowpack.connection_reset_total").increment(1);
            *self.inner = LinkState::Reconnecting;
            // inner (OwnedMutexGuard) is released when drop() returns, before
            // the spawned task runs, so no deadlock.
            tokio::spawn(reconnect_task(Arc::clone(&self.link)));
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::DuplexStream;

    use crate::{auth::AuthHeader, SignatureKeypair, TransportKeypair, accept};

    fn peer_credentials(cluster: &SignatureKeypair, id: u32) -> Credentials {
        let keypair = TransportKeypair::generate().unwrap();
        let auth = AuthHeader::new(NodeId::from(id), None, &keypair.public)
            .sign(&cluster.private);
        Credentials {
            private_key: keypair.private,
            auth_header: auth,
            verification_key: cluster.public.clone(),
        }
    }

    /// A connector backed by a single pre-built DuplexStream.
    struct OneShotConnector(Mutex<Option<DuplexStream>>);

    impl OneShotConnector {
        fn new(stream: DuplexStream) -> Self {
            Self(Mutex::new(Some(stream)))
        }
    }

    impl Connector for OneShotConnector {
        type Stream = DuplexStream;
        fn connect(&self) -> impl Future<Output = Result<DuplexStream, ConnectionError>> + Send {
            let stream = self.0.lock().unwrap().take().unwrap();
            async move { Ok(stream) }
        }
    }

    /// A connector that counts calls and always fails.
    struct FailConnector(Arc<AtomicU32>);

    impl Connector for FailConnector {
        type Stream = DuplexStream;
        fn connect(&self) -> impl Future<Output = Result<DuplexStream, ConnectionError>> + Send {
            self.0.fetch_add(1, Ordering::SeqCst);
            async move {
                Err(ConnectionError::Io(std::io::Error::other("fail")))
            }
        }
    }

    /// Set up a matched client/server pair using a duplex stream and return
    /// (pool_for_client, server_tx, server_rx).
    async fn make_pool_and_server() -> (
        ConnectionPool<OneShotConnector>,
        MessageTx<WriteHalf<DuplexStream>>,
        MessageRx<ReadHalf<DuplexStream>>,
    ) {
        let (client_stream, server_stream) = tokio::io::duplex(65536);

        let cluster = SignatureKeypair::generate().unwrap();
        let client_creds = peer_credentials(&cluster, 1);
        let server_creds = peer_credentials(&cluster, 2);

        let server_auth = server_creds.auth_header.clone();
        let server_private = server_creds.private_key.clone();
        let server_vk = server_creds.verification_key.clone();

        let (server_result, pool) = tokio::join!(
            async move {
                accept::<_>(server_stream, &server_private, &server_auth, &server_vk).await
            },
            async move {
                let pool: ConnectionPool<OneShotConnector> = ConnectionPool::new(Arc::new(client_creds));
                let target = NodeId::from(2u32);
                pool.peer(target.clone(), || OneShotConnector::new(client_stream));
                // Give the background task time to complete the handshake.
                tokio::time::sleep(Duration::from_millis(50)).await;
                pool
            }
        );

        let ((server_tx, server_rx), _) = server_result.unwrap();
        (pool, server_tx, server_rx)
    }

    #[tokio::test]
    async fn wait_connected_does_not_reset_connection() {
        let (pool, _server_tx, _server_rx) = make_pool_and_server().await;
        let target = NodeId::from(2u32);
        let conn = pool.peer(target, || unreachable!("should reuse"));

        let result = conn.wait_connected(Duration::from_millis(100)).await;
        assert!(result.is_ok(), "should be Connected after handshake");

        // The bug: wait_connected previously dirty-dropped a Guard, resetting the
        // link to Reconnecting. Verify the connection is still usable.
        assert!(conn.acquire().await.is_ok(), "wait_connected must not reset the connection");
    }

    #[tokio::test]
    async fn acquire_succeeds_after_handshake() {
        let (pool, _server_tx, _server_rx) = make_pool_and_server().await;
        let target = NodeId::from(2u32);
        let conn = pool.peer(target, || unreachable!("should reuse"));
        let guard = conn.acquire().await;
        assert!(guard.is_ok(), "should be Connected after handshake");
    }

    #[tokio::test]
    async fn acquire_returns_not_ready_while_reconnecting() {
        let cluster = SignatureKeypair::generate().unwrap();
        let creds = peer_credentials(&cluster, 1);
        let attempt_count = Arc::new(AtomicU32::new(0));
        let pool: ConnectionPool<FailConnector> = ConnectionPool::new(Arc::new(creds));
        let target = NodeId::from(2u32);
        let count = Arc::clone(&attempt_count);
        pool.peer(target.clone(), || FailConnector(count));
        // Give the background task a chance to attempt (and fail) once.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let conn = pool.peer(target, || unreachable!());
        assert!(conn.acquire().await.is_err(), "should be NotReady while reconnecting");
    }

    #[tokio::test]
    async fn dirty_drop_resets_connection() {
        let (pool, server_tx, server_rx) = make_pool_and_server().await;
        let target = NodeId::from(2u32);
        let conn = pool.peer(target.clone(), || unreachable!());

        // Acquire and drop without committing → should mark as Reconnecting.
        {
            let guard = conn.acquire().await.unwrap();
            drop(guard); // dirty drop
        }

        // Give the spawned reconnect task time to set state back to Reconnecting.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Next acquire should see Reconnecting (the server side is gone now).
        let conn2 = pool.peer(target, || unreachable!());
        assert!(conn2.acquire().await.is_err(), "should be Reconnecting after dirty drop");
        drop((server_tx, server_rx));
    }

    #[tokio::test]
    async fn commit_keeps_connection_live() {
        let (pool, mut server_tx, mut server_rx) = make_pool_and_server().await;
        let target = NodeId::from(2u32);
        let conn = pool.peer(target.clone(), || unreachable!());

        // Two back-to-back successful exchanges on the same connection.
        for _ in 0..2 {
            let mut guard = conn.acquire().await.expect("Connected");
            let (tx, _rx) = guard.transport();
            tx.send_message(1u8, &[42u8]).await.unwrap();
            server_rx.read_message().await.unwrap();
            server_tx.send_message(1u8, &[99u8]).await.unwrap();
            let (_tx, rx) = guard.transport();
            rx.read_message().await.unwrap();
            guard.commit();
        }

        // After two committed exchanges the connection is still live.
        assert!(conn.acquire().await.is_ok(), "should still be Connected");
    }
}
