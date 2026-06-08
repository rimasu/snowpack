use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use snowpack::{AuthHeader, NodeId, SignatureKeypair, SignedAuthHeader, TransportKeypair, accept, connect};
use tokio::io::duplex;
use tokio::net::{TcpListener, TcpStream};

fn node_creds(cluster: &SignatureKeypair, id: u32) -> (TransportKeypair, SignedAuthHeader) {
    let kp = TransportKeypair::generate().unwrap();
    let auth = AuthHeader::new(NodeId::from(id), None, &kp.public).sign(&cluster.private);
    (kp, auth)
}

// ── Handshake ─────────────────────────────────────────────────────────────────
//
// Full XX Noise handshake over an in-memory duplex stream: key generation,
// three message exchanges, auth header verification.  A regression here means
// crypto or auth overhead has grown.

fn bench_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    c.bench_function("handshake/duplex", |b| {
        b.iter(|| {
            rt.block_on(async {
                let cluster = SignatureKeypair::generate().unwrap();
                let (c_kp, c_auth) = node_creds(&cluster, 1);
                let (s_kp, s_auth) = node_creds(&cluster, 2);
                let (cs, ss) = duplex(65536);
                let _ = tokio::join!(
                    connect(cs, &c_kp.private, &c_auth, &cluster.public),
                    accept(ss, &s_kp.private, &s_auth, &cluster.public),
                );
            });
        });
    });
}

// ── Round-trip latency ────────────────────────────────────────────────────────
//
// Two transports, two payload sizes:
//
//   duplex       – in-memory pipe; no OS network stack.  Isolates crypto and
//                  framing overhead from everything else.
//
//   tcp_loopback – real TCP sockets on 127.0.0.1.  This is the transport that
//                  catches framing bugs: a split 2-byte length write with Nagle
//                  enabled produced ~40 ms here; single-syscall framing with
//                  TCP_NODELAY should be well under 1 ms.

fn bench_round_trip(c: &mut Criterion) {
    const SIZES: &[usize] = &[32, 1024];

    // ── setup: duplex ─────────────────────────────────────────────────────────

    let rt_duplex = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let cluster = SignatureKeypair::generate().unwrap();
    let (c_kp, c_auth) = node_creds(&cluster, 1);
    let (s_kp, s_auth) = node_creds(&cluster, 2);
    let (cs, ss) = duplex(1 << 20);

    let ((mut ctx, mut crx), (mut stx, mut srx)) = rt_duplex.block_on(async {
        let (r1, r2) = tokio::join!(
            connect(cs, &c_kp.private, &c_auth, &cluster.public),
            accept(ss, &s_kp.private, &s_auth, &cluster.public),
        );
        (r1.unwrap().0, r2.unwrap().0)
    });

    // ── setup: tcp_loopback ───────────────────────────────────────────────────

    let rt_tcp = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let cluster = SignatureKeypair::generate().unwrap();
    let (c_kp, c_auth) = node_creds(&cluster, 1);
    let (s_kp, s_auth) = node_creds(&cluster, 2);

    let (mut ctx_tcp, mut crx_tcp) = rt_tcp.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cluster_pub = cluster.public.clone();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let ((mut stx, mut srx), _) =
                accept(stream, &s_kp.private, &s_auth, &cluster_pub).await.unwrap();
            loop {
                let Ok(msg) = srx.read_message().await else { break };
                let Ok(bytes) = msg.read_bytes().await else { break };
                let owned = bytes.to_vec();
                if stx.send_message(1u8, &owned).await.is_err() {
                    break;
                }
            }
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let ((tx, rx), _) =
            connect(stream, &c_kp.private, &c_auth, &cluster.public).await.unwrap();
        (tx, rx)
    });

    // ── benchmarks ────────────────────────────────────────────────────────────

    let mut group = c.benchmark_group("round_trip");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let payload = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("duplex", size), &payload, |b, payload| {
            b.iter(|| {
                rt_duplex.block_on(async {
                    ctx.send_message(1u8, payload).await.unwrap();
                    let msg = srx.read_message().await.unwrap();
                    let owned = msg.read_bytes().await.unwrap().to_vec();
                    stx.send_message(1u8, &owned).await.unwrap();
                    let msg = crx.read_message().await.unwrap();
                    criterion::black_box(msg.read_bytes().await.unwrap());
                });
            });
        });

        group.bench_with_input(
            BenchmarkId::new("tcp_loopback", size),
            &payload,
            |b, payload| {
                b.iter(|| {
                    rt_tcp.block_on(async {
                        ctx_tcp.send_message(1u8, payload).await.unwrap();
                        let msg = crx_tcp.read_message().await.unwrap();
                        criterion::black_box(msg.read_bytes().await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_handshake, bench_round_trip);
criterion_main!(benches);
