require "spec_helper"
require_relative "../../simulator/trace_generator"
require_relative "../../simulator/span_generator"

RSpec.describe SpanGenerator do
  let(:trace) do
    TraceGenerator.new(seed: 1).generate(
      agent_id:   "support-agent",
      task_name:  "classify_customer_ticket",
      start_time: Time.utc(2026, 3, 7, 12, 0, 0)
    )
  end

  let(:seeded) { SpanGenerator.new(seed: 42) }

  describe "SEQUENCE" do
    it "contains exactly 7 span types" do
      expect(SpanGenerator::SEQUENCE.length).to eq(7)
    end

    it "starts with agent_run_started" do
      expect(SpanGenerator::SEQUENCE.first).to eq("agent_run_started")
    end

    it "ends with run_completed" do
      expect(SpanGenerator::SEQUENCE.last).to eq("run_completed")
    end

    it "contains only valid SPAN_TYPES" do
      expect(SPAN_TYPES).to include(*SpanGenerator::SEQUENCE)
    end

    it "is frozen" do
      expect(SpanGenerator::SEQUENCE).to be_frozen
    end
  end

  describe "PARENT_INDICES" do
    it "has the same length as SEQUENCE" do
      expect(SpanGenerator::PARENT_INDICES.length).to eq(SpanGenerator::SEQUENCE.length)
    end

    it "has nil as the first entry (root span has no parent)" do
      expect(SpanGenerator::PARENT_INDICES.first).to be_nil
    end

    it "all non-nil indices are valid positions in SEQUENCE" do
      SpanGenerator::PARENT_INDICES.compact.each do |idx|
        expect(idx).to be < SpanGenerator::SEQUENCE.length
      end
    end

    it "is frozen" do
      expect(SpanGenerator::PARENT_INDICES).to be_frozen
    end
  end

  describe "#generate_sequence" do
    subject(:spans) { seeded.generate_sequence(trace: trace) }

    it "returns an array of TelemetryEvent objects" do
      expect(spans).to all(be_a(TelemetryEvent))
    end

    it "returns exactly 7 spans" do
      expect(spans.length).to eq(7)
    end

    it "assigns sequential span IDs s1 through s7" do
      expect(spans.map(&:span_id)).to eq(%w[s1 s2 s3 s4 s5 s6 s7])
    end

    it "sets the root span (agent_run_started) parent_span_id to nil" do
      root = spans.find { |s| s.span_type == "agent_run_started" }
      expect(root.parent_span_id).to be_nil
    end

    it "sets model_call parent to s1 (agent_run_started)" do
      model_call = spans.find { |s| s.span_type == "model_call" }
      expect(model_call.parent_span_id).to eq("s1")
    end

    it "sets run_completed parent to s1 (agent_run_started)" do
      run_completed = spans.find { |s| s.span_type == "run_completed" }
      expect(run_completed.parent_span_id).to eq("s1")
    end

    it "sets decision parent to s3 (model_response)" do
      decision = spans.find { |s| s.span_type == "decision" }
      expect(decision.parent_span_id).to eq("s3")
    end

    it "propagates trace_id to all spans" do
      expect(spans.map(&:trace_id).uniq).to eq([trace.trace_id])
    end

    it "propagates agent_id to all spans" do
      expect(spans.map(&:agent_id).uniq).to eq([trace.agent_id])
    end

    it "produces monotonically increasing timestamps" do
      times = spans.map { |s| Time.parse(s.timestamp) }
      expect(times).to eq(times.sort)
    end

    it "all timestamps are at or after the trace start_time" do
      start = Time.parse(trace.start_time)
      spans.each { |s| expect(Time.parse(s.timestamp)).to be >= start }
    end

    it "populates metadata for every span" do
      spans.each { |s| expect(s.metadata).not_to be_empty }
    end

    it "agent_run_started metadata includes task key" do
      root = spans.find { |s| s.span_type == "agent_run_started" }
      expect(root.metadata).to include("task")
    end

    it "model_call metadata includes model_name, prompt_tokens, latency_ms, and temperature" do
      mc = spans.find { |s| s.span_type == "model_call" }
      expect(mc.metadata.keys).to include("model_name", "prompt_tokens", "latency_ms", "temperature")
    end

    it "model_call latency_ms is within realistic range" do
      mc = spans.find { |s| s.span_type == "model_call" }
      expect(mc.metadata["latency_ms"]).to be_between(300, 4000)
    end

    it "model_response metadata includes completion_tokens, output_preview, and stop_reason" do
      mr = spans.find { |s| s.span_type == "model_response" }
      expect(mr.metadata.keys).to include("completion_tokens", "output_preview", "stop_reason")
    end

    it "model_response stop_reason is a known value" do
      mr = spans.find { |s| s.span_type == "model_response" }
      expect(SpanGenerator::STOP_REASONS).to include(mr.metadata["stop_reason"])
    end

    it "tool_call metadata includes tool_name and arguments" do
      tc = spans.find { |s| s.span_type == "tool_call" }
      expect(tc.metadata.keys).to include("tool_name", "arguments")
    end

    it "tool_call arguments is a non-empty hash" do
      tc = spans.find { |s| s.span_type == "tool_call" }
      expect(tc.metadata["arguments"]).to be_a(Hash).and(be_any)
    end

    it "tool_result metadata includes latency_ms" do
      tr = spans.find { |s| s.span_type == "tool_result" }
      expect(tr.metadata.keys).to include("latency_ms")
    end

    it "decision metadata includes action, confidence, and reasoning" do
      d = spans.find { |s| s.span_type == "decision" }
      expect(d.metadata.keys).to include("action", "confidence", "reasoning")
    end

    it "decision reasoning is a non-empty string" do
      d = spans.find { |s| s.span_type == "decision" }
      expect(d.metadata["reasoning"]).to be_a(String)
      expect(d.metadata["reasoning"]).not_to be_empty
    end
  end

  describe "determinism" do
    it "produces identical sequences for the same seed" do
      gen_a = SpanGenerator.new(seed: 7)
      gen_b = SpanGenerator.new(seed: 7)
      expect(gen_a.generate_sequence(trace: trace)).to eq(gen_b.generate_sequence(trace: trace))
    end

    it "produces different sequences for different seeds" do
      spans_a = SpanGenerator.new(seed: 1).generate_sequence(trace: trace)
      spans_b = SpanGenerator.new(seed: 2).generate_sequence(trace: trace)
      expect(spans_a.map(&:timestamp)).not_to eq(spans_b.map(&:timestamp))
    end
  end

  describe "#generate_single" do
    it "returns a single TelemetryEvent" do
      event = seeded.generate_single(
        span_type: "error",
        trace:     trace,
        span_id:   "s8"
      )
      expect(event).to be_a(TelemetryEvent)
    end

    it "sets the correct span_type" do
      event = seeded.generate_single(span_type: "error", trace: trace, span_id: "s8")
      expect(event.span_type).to eq("error")
    end

    it "populates error metadata with message and code" do
      event = seeded.generate_single(span_type: "error", trace: trace, span_id: "s8")
      expect(event.metadata.keys).to include("message", "code")
    end

    it "accepts an explicit parent_span_id" do
      event = seeded.generate_single(
        span_type:      "error",
        trace:          trace,
        span_id:        "s8",
        parent_span_id: "s3"
      )
      expect(event.parent_span_id).to eq("s3")
    end

    it "accepts an explicit timestamp" do
      fixed = Time.utc(2026, 3, 7, 12, 5, 0)
      event = seeded.generate_single(
        span_type:  "error",
        trace:      trace,
        span_id:    "s8",
        timestamp:  fixed
      )
      expect(event.timestamp).to eq("2026-03-07T12:05:00Z")
    end

    it "carries the trace's trace_id and agent_id" do
      event = seeded.generate_single(span_type: "decision", trace: trace, span_id: "s9")
      expect(event.trace_id).to eq(trace.trace_id)
      expect(event.agent_id).to eq(trace.agent_id)
    end
  end
end
