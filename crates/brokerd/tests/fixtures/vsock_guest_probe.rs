//! Disposable VM fixture exercising the broker's real host-peer validation.

use std::io;
use std::time::Duration;

use microsandbox_brokerd::vsock::VsockListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err(io::Error::other(
            "usage: vsock-guest-probe PORT READY_FILE TOKEN",
        ));
    }
    let port = args[1].parse().map_err(io::Error::other)?;
    let listener = VsockListener::bind(port)?;
    std::fs::write(&args[2], &args[3])?;
    loop {
        let mut stream = listener.accept().await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let length = stream.read_u32().await? as usize;
            if length > 4096 {
                return Err(io::Error::other("probe frame too large"));
            }
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).await?;
            stream.write_all(&payload).await?;
            stream.shutdown().await
        })
        .await
        .map_err(io::Error::other)??;
    }
}
