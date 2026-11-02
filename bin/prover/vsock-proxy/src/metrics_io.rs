use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use metrics::Counter;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Counts bytes written, including partial transfers before a session fails.
pub(crate) struct MeteredStream<T> {
    /// Transport being forwarded to.
    pub(crate) inner: T,
    /// Successfully written bytes for this direction.
    pub(crate) bytes: Counter,
}

impl<T: AsyncRead + Unpin> AsyncRead for MeteredStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MeteredStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            self.bytes.increment(written as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_partial_writes_without_counting_reads_or_failed_writes() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let (inner, mut peer) = tokio::io::duplex(3);
            let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let mut stream = MeteredStream {
                inner,
                bytes: Counter::from_arc(Arc::clone(&count)),
            };
            assert_eq!(stream.write(b"catnip").await.unwrap(), 3);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx, b"nip")
                    .is_pending()
            );
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 3);
            let mut buf = [0; 3];
            peer.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"cat");

            peer.write_all(b"ok").await.unwrap();
            let mut reply = [0; 2];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok");
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 3);

            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(peer.read(&mut buf).await.unwrap(), 0);
            drop(peer);
            assert_eq!(
                stream.write(b"x").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 3);
        })
        .await
        .unwrap();
    }
}
