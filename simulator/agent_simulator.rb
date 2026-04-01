require "json"
require_relative "trace_generator"
require_relative "span_generator"

# Immutable value object representing a complete simulated agent execution —
# a finalized Trace paired with its ordered array of TelemetryEvent spans.
SimulatedRun = Data.define(:trace, :spans)

class SimulatedRun
  def to_h
    { "trace" => trace.to_h, "spans" => spans.map(&:to_h) }
  end

  def to_json(*args) = to_h.to_json(*args)
end

# Orchestrates TraceGenerator and SpanGenerator to produce complete simulated
# agent execution runs.
#
# Failure simulation: each run has a configurable probability of failure
# (default 15%). On failure, an error span is injected and the trace status
# is finalized to "error"; on success both are finalized to "success".
#
# Seed propagation: the master seed derives independent child seeds for
# TraceGenerator and SpanGenerator so their random streams don't interfere.
#
# Usage:
#   sim = AgentSimulator.new(seed: 42)
#   run = sim.run
#   puts run.to_json
class AgentSimulator
  FAILURE_RATE = 0.15

  def initialize(seed: nil, failure_rate: FAILURE_RATE)
    @rng          = seed ? Random.new(seed) : Random.new
    @failure_rate = failure_rate
    @trace_gen    = TraceGenerator.new(seed: @rng.rand(0..2**32))
    @span_gen     = SpanGenerator.new(seed:  @rng.rand(0..2**32))
  end

  # Produces one complete SimulatedRun with a finalized trace and span sequence.
  #
  # @param agent_id   [String, nil] override agent type selection
  # @param task_name  [String, nil] override task name selection
  # @param start_time [Time] defaults to current UTC time
  # @return [SimulatedRun]
  def run(agent_id: nil, task_name: nil, start_time: Time.now.utc)
    trace = @trace_gen.generate(agent_id: agent_id, task_name: task_name, start_time: start_time)
    spans = @span_gen.generate_sequence(trace: trace)

    if @rng.rand < @failure_rate
      spans = inject_error(spans, trace)
      trace = trace.with(status: "error")
    else
      trace = trace.with(status: "success")
    end

    SimulatedRun.new(trace: trace, spans: spans)
  end

  # Runs a simulation and returns the output as NDJSON (newline-delimited JSON) —
  # one JSON object per line, suitable for ingestion by an observability platform.
  #
  # Format:
  #   Line 1:   trace record  { trace_id, agent_id, task_name, start_time, status }
  #   Lines 2+: span events   { trace_id, span_id, parent_span_id, span_type, ... }
  #
  # @param agent_id   [String, nil]
  # @param task_name  [String, nil]
  # @param start_time [Time]
  # @return [String] NDJSON — each line is a valid JSON object
  def emit(agent_id: nil, task_name: nil, start_time: Time.now.utc)
    simulated_run = run(agent_id: agent_id, task_name: task_name, start_time: start_time)
    ([simulated_run.trace.to_json] + simulated_run.spans.map(&:to_json)).join("\n")
  end

  private

  # Injects an error span before run_completed and marks run_completed as failed.
  # Error span: span_id "s8", parented to the decision span (s6).
  def inject_error(spans, trace)
    run_completed = spans.last.with(metadata: { "status" => "error" })
    error_span    = @span_gen.generate_single(
      span_type:      "error",
      trace:          trace,
      span_id:        "s8",
      parent_span_id: "s6",
      timestamp:      Time.parse(run_completed.timestamp)
    )
    spans[0..-2] + [error_span, run_completed]
  end
end
