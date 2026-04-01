require "json"

# Canonical span types for agent telemetry events.
SPAN_TYPES = %w[
  agent_run_started
  model_call
  model_response
  tool_call
  tool_result
  decision
  error
  run_completed
].freeze

# Expected metadata keys per span type.
# Used by SpanGenerator to build realistic, well-shaped payloads.
METADATA_SCHEMA = {
  "agent_run_started" => { task: String },
  "model_call"        => { model_name: String, prompt_tokens: Integer },
  "model_response"    => { completion_tokens: Integer, output_preview: String },
  "tool_call"         => { tool_name: String, arguments: Hash },
  "tool_result"       => { tool_name: String, success: [TrueClass, FalseClass], result: String },
  "decision"          => { action: String, confidence: Float },
  "error"             => { message: String, code: String },
  "run_completed"     => { status: String }
}.freeze

# Immutable value object representing a single telemetry event emitted by the simulator.
#
# Fields:
#   trace_id       — identifies the parent trace
#   span_id        — unique identifier for this span
#   parent_span_id — nil for root spans
#   span_type      — one of the 8 values in SPAN_TYPES
#   timestamp      — ISO 8601 UTC string (e.g. "2026-03-07T12:01:02Z")
#   agent_id       — identifies the agent that emitted this event
#   metadata       — structured Hash whose shape is defined by METADATA_SCHEMA
TelemetryEvent = Data.define(
  :trace_id,
  :span_id,
  :parent_span_id,
  :span_type,
  :timestamp,
  :agent_id,
  :metadata
) do
  # Validated constructor. Raises ArgumentError for unknown span types.
  def self.build(trace_id:, span_id:, span_type:, timestamp:, agent_id:, metadata:,
                 parent_span_id: nil)
    unless SPAN_TYPES.include?(span_type)
      raise ArgumentError, "Unknown span_type '#{span_type}'. Must be one of: #{SPAN_TYPES.join(', ')}"
    end

    new(
      trace_id: trace_id,
      span_id: span_id,
      parent_span_id: parent_span_id,
      span_type: span_type,
      timestamp: timestamp,
      agent_id: agent_id,
      metadata: metadata
    )
  end

  def to_json(*args)
    to_h.to_json(*args)
  end
end
