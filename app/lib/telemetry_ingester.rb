# Parses an NDJSON payload from the telemetry API and persists it to the database.
#
# Format (matches AgentSimulator#emit output):
#   Line 1:   trace record  { trace_id, agent_id, task_name, start_time, status }
#   Lines 2+: span records  { trace_id, span_id, parent_span_id, span_type, timestamp, agent_id, metadata }
#
# Usage:
#   result = TelemetryIngester.call(ndjson_string)
#   # => { trace_id: "a1b2...", spans_ingested: 7 }
#
# Raises TelemetryIngester::Error on invalid input or validation failure.
# All DB writes are wrapped in a single transaction — all succeed or all roll back.
class TelemetryIngester
  Error = Class.new(StandardError)

  def self.call(ndjson)
    new(ndjson).call
  end

  def initialize(ndjson)
    @lines = ndjson.to_s.split("\n").map(&:strip).reject(&:empty?)
  end

  def call
    raise Error, "payload is empty" if @lines.empty?

    trace_data = parse_json(@lines.first)
    span_lines  = @lines[1..]

    raise Error, "payload must contain at least one span" if span_lines.empty?

    ActiveRecord::Base.transaction do
      trace = persist_trace(trace_data)
      spans = span_lines.map { |line| persist_span(parse_json(line), trace.trace_id) }
      { trace_id: trace.trace_id, spans_ingested: spans.length }
    end
  rescue ActiveRecord::RecordInvalid => e
    raise Error, e.message
  end

  private

  def parse_json(line)
    JSON.parse(line)
  rescue JSON::ParserError => e
    raise Error, "invalid JSON: #{e.message}"
  end

  def persist_trace(data)
    Trace.create!(
      trace_id:   data["trace_id"],
      agent_id:   data["agent_id"],
      task_name:  data["task_name"],
      start_time: data["start_time"],
      status:     data["status"] || "in_progress"
    )
  end

  def persist_span(data, trace_id)
    Span.create!(
      trace_id:       trace_id,
      span_id:        data["span_id"],
      parent_span_id: data["parent_span_id"],
      span_type:      data["span_type"],
      timestamp:      data["timestamp"],
      agent_id:       data["agent_id"],
      metadata:       data["metadata"] || {}
    )
  end
end
