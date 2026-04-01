require "json"
require "time"
require_relative "telemetry_event"

# Generates sequences of TelemetryEvent spans for a simulated agent run.
#
# The fixed SEQUENCE defines the canonical 7-step span lifecycle. PARENT_INDICES
# encodes the tree structure as positional references into SEQUENCE — this keeps
# parent relationships explicit without requiring a recursive data structure.
#
# Pass a seed for deterministic output (required for repeatable tests):
#   SpanGenerator.new(seed: 42).generate_sequence(trace: trace)
class SpanGenerator
  SEQUENCE = %w[
    agent_run_started
    model_call
    model_response
    tool_call
    tool_result
    decision
    run_completed
  ].freeze

  # Each entry is the index of the parent span in SEQUENCE, or nil for the root.
  # agent_run_started(nil) → model_call(0) → model_response(1) → tool_call(2) → tool_result(3)
  #                                                             → decision(2)
  #                        → run_completed(0)
  PARENT_INDICES = [nil, 0, 1, 2, 3, 2, 0].freeze

  MODEL_NAMES      = %w[claude-sonnet-4-6 claude-opus-4-6 gpt-4o].freeze
  TOOL_NAMES       = %w[search lookup fetch write classify summarize].freeze
  DECISION_ACTIONS = %w[escalate retry complete skip delegate].freeze
  RESULT_VALUES    = %w[ok not_found partial error timeout].freeze
  ERROR_CODES      = %w[TIMEOUT NOT_FOUND RATE_LIMITED INVALID_INPUT UNKNOWN].freeze
  STOP_REASONS     = %w[end_turn max_tokens stop_sequence].freeze

  ERROR_MESSAGES = [
    "Request timed out after 30s",
    "Resource not found",
    "Rate limit exceeded",
    "Invalid input format",
    "Unexpected internal error"
  ].freeze

  DECISION_REASONING = [
    "Confidence threshold met, proceeding with action",
    "Tool result indicates partial success, retrying",
    "Escalating due to low confidence score",
    "Task complete, all steps resolved successfully",
    "Delegating to specialized agent for further processing"
  ].freeze

  def initialize(seed: nil)
    @rng = seed ? Random.new(seed) : Random.new
  end

  # Returns Array<TelemetryEvent> — one event per step in SEQUENCE.
  # Timestamps advance from trace.start_time by a random 5–500ms per span.
  # Span IDs are sequential: "s1" through "s7".
  #
  # @param trace [Trace]
  # @return [Array<TelemetryEvent>]
  def generate_sequence(trace:)
    span_ids     = SEQUENCE.each_index.map { |i| "s#{i + 1}" }
    current_time = Time.parse(trace.start_time)

    SEQUENCE.each_with_index.map do |span_type, i|
      current_time += @rng.rand(5..500) / 1000.0
      parent_index  = PARENT_INDICES[i]

      TelemetryEvent.build(
        trace_id:       trace.trace_id,
        span_id:        span_ids[i],
        parent_span_id: parent_index ? span_ids[parent_index] : nil,
        span_type:      span_type,
        timestamp:      current_time.utc.iso8601,
        agent_id:       trace.agent_id,
        metadata:       build_metadata(span_type, trace.task_name)
      )
    end
  end

  # Returns a single TelemetryEvent for an arbitrary span type.
  # Used by AgentSimulator to inject spans outside the default sequence
  # (e.g. an error span on failure).
  #
  # @param span_type      [String]
  # @param trace          [Trace]
  # @param span_id        [String]
  # @param parent_span_id [String, nil]
  # @param timestamp      [Time, nil] defaults to current UTC time
  # @return [TelemetryEvent]
  def generate_single(span_type:, trace:, span_id:, parent_span_id: nil, timestamp: nil)
    TelemetryEvent.build(
      trace_id:       trace.trace_id,
      span_id:        span_id,
      parent_span_id: parent_span_id,
      span_type:      span_type,
      timestamp:      (timestamp || Time.now.utc).iso8601,
      agent_id:       trace.agent_id,
      metadata:       build_metadata(span_type, trace.task_name)
    )
  end

  private

  def build_metadata(span_type, task_name)
    case span_type
    when "agent_run_started"
      { "task" => task_name }
    when "model_call"
      {
        "model_name"   => MODEL_NAMES.sample(random: @rng),
        "prompt_tokens" => @rng.rand(100..2000),
        "latency_ms"   => @rng.rand(300..4000),
        "temperature"  => (@rng.rand * 0.8 + 0.2).round(1)
      }
    when "model_response"
      {
        "completion_tokens" => @rng.rand(50..800),
        "output_preview"    => "Processing: #{task_name}",
        "stop_reason"       => STOP_REASONS.sample(random: @rng)
      }
    when "tool_call"
      tool = TOOL_NAMES.sample(random: @rng)
      { "tool_name" => tool, "arguments" => build_tool_arguments(tool, task_name) }
    when "tool_result"
      tool = TOOL_NAMES.sample(random: @rng)
      {
        "tool_name"  => tool,
        "success"    => (@rng.rand < 0.85),
        "result"     => RESULT_VALUES.sample(random: @rng),
        "latency_ms" => @rng.rand(20..800)
      }
    when "decision"
      {
        "action"     => DECISION_ACTIONS.sample(random: @rng),
        "confidence" => (@rng.rand * 0.5 + 0.5).round(2),
        "reasoning"  => DECISION_REASONING.sample(random: @rng)
      }
    when "error"
      { "message" => ERROR_MESSAGES.sample(random: @rng), "code" => ERROR_CODES.sample(random: @rng) }
    when "run_completed"
      { "status" => "success" }
    end
  end

  def build_tool_arguments(tool, task_name)
    case tool
    when "search"
      { "query" => task_name, "max_results" => @rng.rand(3..10) }
    when "lookup"
      { "id" => @rng.bytes(4).unpack1("H*"), "fields" => %w[name status type].sample(@rng.rand(2..3), random: @rng) }
    when "fetch"
      { "url" => "https://api.internal/#{task_name.gsub('_', '-')}", "timeout_ms" => @rng.rand(1000..5000) }
    when "write"
      { "destination" => "output/#{task_name}.json", "format" => "json" }
    when "classify"
      { "input" => task_name, "categories" => %w[urgent normal low].sample(@rng.rand(2..3), random: @rng) }
    when "summarize"
      { "input_length" => @rng.rand(500..5000), "max_length" => @rng.rand(100..500) }
    else
      { "query" => task_name }
    end
  end
end
