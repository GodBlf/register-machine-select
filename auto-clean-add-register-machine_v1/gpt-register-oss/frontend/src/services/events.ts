export function connectLogStream(): EventSource {
  return new EventSource("/api/logs");
}
