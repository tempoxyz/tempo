use crate::{
    config::Metrics,
    journal::{SharedJournal, lock},
    model::{Class, Phase, State},
};
use anyhow::Result;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

pub fn render(journal: &SharedJournal, config: &Metrics) -> Result<String> {
    let j = lock(journal)?;
    let s = &j.state;
    let c = &s.counts;
    let mut text = String::new();
    macro_rules! metric {
        ($name:literal, $kind:literal, $value:expr) => {
            text.push_str(&format!(
                "# TYPE tempo_replay_{} {}\ntempo_replay_{} {}\n",
                $name, $kind, $name, $value
            ));
        };
    }
    metric!("user_occurrences", "gauge", c.user_occurrences);
    metric!("system_occurrences", "gauge", c.system_occurrences);
    metric!("offered_occurrences", "gauge", c.offered);
    metric!("finalized_occurrences", "gauge", c.finalized);
    metric!("gap_occurrences", "gauge", c.gaps);
    metric!("rpc_attempts_total", "counter", c.attempts);
    metric!("receipt_mismatches", "gauge", c.receipt_mismatches);
    metric!("reserved_occurrences", "gauge", c.reserved_count);
    metric!("reserved_raw_bytes", "gauge", c.reserved_bytes);
    metric!(
        "coverage_degraded",
        "gauge",
        u8::from(c.gaps > 0 || c.subblock_occurrences > 0)
    );
    metric!("observed_lag_ms", "gauge", s.lag_ms);
    metric!("schedule_slip_ms", "gauge", s.slip_ms);
    metric!(
        "capture_unavailable",
        "gauge",
        u8::from(s.capture_error.is_some())
    );
    metric!("paused_incident", "gauge", u8::from(s.incident.is_some()));
    metric!(
        "submission_coverage",
        "gauge",
        ratio(c.offered, c.user_occurrences)
    );
    metric!(
        "inclusion_coverage",
        "gauge",
        ratio(c.finalized, c.user_occurrences)
    );
    let cursors = [
        (
            "captured",
            s.cursors.captured_through.as_ref().map(|p| p.height),
        ),
        ("dispatch_accounted", s.cursors.dispatch_accounted_through),
        ("accounted", s.cursors.accounted_through),
        ("included", s.cursors.included_through),
        (
            "shadow_observed",
            s.cursors.shadow_observed_through.as_ref().map(|p| p.height),
        ),
    ];
    for (name, cursor) in cursors {
        if let Some(h) = cursor {
            text.push_str(&format!(
                "tempo_replay_cursor_height{{cursor=\"{name}\"}} {h}\n"
            ));
        }
    }
    for phase in [
        Phase::CaptureOnly,
        Phase::Verify,
        Phase::Reconcile,
        Phase::CatchUp,
        Phase::Live,
        Phase::PausedIncident,
    ] {
        text.push_str(&format!(
            "tempo_replay_phase{{phase=\"{phase:?}\"}} {}\n",
            u8::from(s.phase == phase)
        ));
    }
    let mut recent_users = 0;
    let mut recent_gaps = 0;
    if let Some(end) = s.last_release_height {
        let start = end
            .saturating_add(1)
            .saturating_sub(config.gap_window_blocks as u64)
            .max(
                s.replay_boundary
                    .map_or(s.first_height, |b| b.saturating_add(1)),
            );
        for h in start..=end {
            for o in j.occurrences(h)? {
                if o.tx.class != Class::System {
                    recent_users += 1;
                    recent_gaps += u64::from(matches!(o.state, State::Gap { .. }));
                }
            }
        }
    }
    let recent_ratio = ratio(recent_gaps, recent_users);
    metric!("recent_gap_fraction", "gauge", recent_ratio);
    metric!(
        "recent_gap_alarm",
        "gauge",
        u8::from(recent_users > 0 && recent_ratio > config.gap_warn_fraction)
    );
    Ok(text)
}
fn ratio(n: u64, d: u64) -> f64 {
    if d == 0 { 0. } else { n as f64 / d as f64 }
}
pub async fn serve(
    listener: TcpListener,
    journal: SharedJournal,
    config: Metrics,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        let accepted = tokio::select! { _ = stop.cancelled() => break, accepted = listener.accept() => accepted? };
        let mut socket = accepted.0;
        let request = async {
            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).await?;
            let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
            let (status, body) = if request.starts_with("GET /metrics ") {
                ("200 OK", render(&journal, &config)?)
            } else if request.starts_with("GET /healthz ") {
                let j = lock(&journal)?;
                if j.state.incident.is_none() && j.state.capture_error.is_none() {
                    ("200 OK", "ok\n".into())
                } else {
                    (
                        "503 Service Unavailable",
                        "paused or source unavailable\n".into(),
                    )
                }
            } else {
                ("404 Not Found", "not found\n".into())
            };
            socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::timeout(Duration::from_secs(2), request) => {} }
    }
    Ok(())
}
