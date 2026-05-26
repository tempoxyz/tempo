function formatDuration(seconds) {
  const totalSeconds = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const secs = totalSeconds % 60;

  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0 || hours > 0) parts.push(`${minutes}m`);
  parts.push(`${secs}s`);
  return parts.join(' ');
}

function elapsedLine(startedAt, now = Date.now()) {
  const started = Number(startedAt);
  if (!Number.isFinite(started) || started <= 0) return '';

  const elapsedSeconds = Math.floor((now - started * 1000) / 1000);
  return `Overall time: \`${formatDuration(elapsedSeconds)}\``;
}

module.exports = { elapsedLine, formatDuration };
