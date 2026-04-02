require "spec_helper"
require_relative "../../simulator/trace_generator"

RSpec.describe TraceGenerator do
  let(:seeded) { TraceGenerator.new(seed: 42) }

  describe "AGENT_TYPES" do
    it "contains exactly 8 agent types" do
      expect(TraceGenerator::AGENT_TYPES.length).to eq(8)
    end

    it "includes all expected agent identifiers" do
      expect(TraceGenerator::AGENT_TYPES).to match_array(
        %w[support-agent research-agent automation-agent triage-agent
           data-agent monitoring-agent code-agent notification-agent]
      )
    end

    it "is frozen" do
      expect(TraceGenerator::AGENT_TYPES).to be_frozen
    end
  end

  describe "TASK_NAMES" do
    it "has an entry for every agent type" do
      expect(TraceGenerator::TASK_NAMES.keys).to match_array(TraceGenerator::AGENT_TYPES)
    end

    it "each agent type has at least one task name" do
      TraceGenerator::TASK_NAMES.each_value do |tasks|
        expect(tasks.length).to be >= 1
      end
    end

    it "is frozen" do
      expect(TraceGenerator::TASK_NAMES).to be_frozen
    end
  end

  describe "#generate" do
    subject(:trace) { seeded.generate }

    it "returns a Trace instance" do
      expect(trace).to be_a(Simulator::Trace)
    end

    it "populates all five fields" do
      expect(trace.trace_id).not_to be_nil
      expect(trace.agent_id).not_to be_nil
      expect(trace.task_name).not_to be_nil
      expect(trace.start_time).not_to be_nil
      expect(trace.status).not_to be_nil
    end

    it "generates a 16-character lowercase hex trace_id" do
      expect(trace.trace_id).to match(/\A[0-9a-f]{16}\z/)
    end

    it "defaults status to 'in_progress'" do
      expect(trace.status).to eq("in_progress")
    end

    it "selects agent_id from AGENT_TYPES" do
      expect(TraceGenerator::AGENT_TYPES).to include(trace.agent_id)
    end

    it "selects task_name from the correct pool for the chosen agent" do
      expect(TraceGenerator::TASK_NAMES[trace.agent_id]).to include(trace.task_name)
    end

    it "sets start_time as an ISO 8601 UTC string" do
      expect(trace.start_time).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
    end
  end

  describe "determinism" do
    it "produces identical traces for the same seed" do
      gen_a = TraceGenerator.new(seed: 99)
      gen_b = TraceGenerator.new(seed: 99)
      expect(gen_a.generate).to eq(gen_b.generate)
    end

    it "produces different traces for different seeds" do
      trace_a = TraceGenerator.new(seed: 1).generate
      trace_b = TraceGenerator.new(seed: 2).generate
      expect(trace_a.trace_id).not_to eq(trace_b.trace_id)
    end
  end

  describe "overrides" do
    it "accepts an explicit agent_id" do
      trace = seeded.generate(agent_id: "triage-agent")
      expect(trace.agent_id).to eq("triage-agent")
    end

    it "accepts an explicit task_name" do
      trace = seeded.generate(task_name: "custom_task")
      expect(trace.task_name).to eq("custom_task")
    end

    it "accepts an explicit start_time" do
      fixed = Time.utc(2026, 1, 15, 9, 0, 0)
      trace = seeded.generate(start_time: fixed)
      expect(trace.start_time).to eq("2026-01-15T09:00:00Z")
    end
  end
end

RSpec.describe Simulator::Trace do
  describe "VALID_STATUSES" do
    it "contains in_progress, success, and error" do
      expect(Simulator::Trace::VALID_STATUSES).to match_array(%w[in_progress success error])
    end
  end

  describe ".build" do
    let(:valid_attrs) do
      {
        trace_id: "abc123def456abcd",
        agent_id: "support-agent",
        task_name: "classify_customer_ticket",
        start_time: "2026-03-07T12:00:00Z",
        status: "in_progress"
      }
    end

    it "constructs a Trace with all fields" do
      trace = Simulator::Trace.build(**valid_attrs)
      expect(trace.trace_id).to eq("abc123def456abcd")
      expect(trace.status).to eq("in_progress")
    end

    it "raises ArgumentError for an unknown status" do
      expect {
        Simulator::Trace.build(**valid_attrs, status: "unknown")
      }.to raise_error(ArgumentError, /unknown/)
    end

    it "raises ArgumentError and names valid statuses" do
      expect {
        Simulator::Trace.build(**valid_attrs, status: "pending")
      }.to raise_error(ArgumentError, /in_progress/)
    end
  end

  describe "#to_json" do
    it "serializes all fields" do
      trace = Simulator::Trace.build(
        trace_id: "abc123def456abcd", agent_id: "triage-agent",
        task_name: "route_support_ticket", start_time: "2026-03-07T12:00:00Z",
        status: "success"
      )
      parsed = JSON.parse(trace.to_json)
      expect(parsed.keys).to match_array(%w[trace_id agent_id task_name start_time status])
      expect(parsed["status"]).to eq("success")
    end
  end
end
