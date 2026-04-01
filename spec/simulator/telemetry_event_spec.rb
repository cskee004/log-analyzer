require "spec_helper"
require_relative "../../simulator/telemetry_event"

RSpec.describe TelemetryEvent do
  let(:valid_attrs) do
    {
      trace_id:       "abc123",
      span_id:        "s1",
      parent_span_id: nil,
      span_type:      "tool_call",
      timestamp:      "2026-03-07T12:01:02Z",
      agent_id:       "test-agent",
      metadata:       { "tool_name" => "lookup", "arguments" => {} }
    }
  end

  describe "SPAN_TYPES" do
    it "contains exactly 8 canonical types" do
      expect(SPAN_TYPES.length).to eq(8)
    end

    it "includes all expected span types" do
      expected = %w[
        agent_run_started model_call model_response tool_call
        tool_result decision error run_completed
      ]
      expect(SPAN_TYPES).to match_array(expected)
    end

    it "is frozen" do
      expect(SPAN_TYPES).to be_frozen
    end
  end

  describe "METADATA_SCHEMA" do
    it "has an entry for every span type" do
      expect(METADATA_SCHEMA.keys).to match_array(SPAN_TYPES)
    end

    it "is frozen" do
      expect(METADATA_SCHEMA).to be_frozen
    end

    it "defines expected keys for tool_call" do
      expect(METADATA_SCHEMA["tool_call"].keys).to include(:tool_name, :arguments)
    end

    it "defines expected keys for model_call" do
      expect(METADATA_SCHEMA["model_call"].keys).to include(:model_name, :prompt_tokens)
    end
  end

  describe ".build" do
    it "constructs a TelemetryEvent with all fields present" do
      event = TelemetryEvent.build(**valid_attrs)

      expect(event.trace_id).to eq("abc123")
      expect(event.span_id).to eq("s1")
      expect(event.parent_span_id).to be_nil
      expect(event.span_type).to eq("tool_call")
      expect(event.timestamp).to eq("2026-03-07T12:01:02Z")
      expect(event.agent_id).to eq("test-agent")
      expect(event.metadata).to eq({ "tool_name" => "lookup", "arguments" => {} })
    end

    it "accepts a parent_span_id when provided" do
      event = TelemetryEvent.build(**valid_attrs, parent_span_id: "s0")
      expect(event.parent_span_id).to eq("s0")
    end

    it "raises ArgumentError for an unknown span_type" do
      expect {
        TelemetryEvent.build(**valid_attrs, span_type: "unknown_type")
      }.to raise_error(ArgumentError, /unknown_type/)
    end

    it "raises ArgumentError and names the valid types" do
      expect {
        TelemetryEvent.build(**valid_attrs, span_type: "bad")
      }.to raise_error(ArgumentError, /agent_run_started/)
    end
  end

  describe "#to_json" do
    it "serializes all fields to JSON" do
      event = TelemetryEvent.build(**valid_attrs)
      parsed = JSON.parse(event.to_json)

      expect(parsed.keys).to match_array(
        %w[trace_id span_id parent_span_id span_type timestamp agent_id metadata]
      )
    end

    it "round-trips metadata correctly" do
      event = TelemetryEvent.build(**valid_attrs)
      parsed = JSON.parse(event.to_json)
      expect(parsed["metadata"]["tool_name"]).to eq("lookup")
    end
  end
end
