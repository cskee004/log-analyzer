require "spec_helper"
require_relative "../../simulator/agent_simulator"

RSpec.describe AgentSimulator do
  let(:success_sim) { AgentSimulator.new(seed: 42, failure_rate: 0.0) }
  let(:failure_sim) { AgentSimulator.new(seed: 42, failure_rate: 1.0) }

  describe "FAILURE_RATE" do
    it "defaults to 0.15" do
      expect(AgentSimulator::FAILURE_RATE).to eq(0.15)
    end
  end

  describe "#run" do
    it "returns a SimulatedRun" do
      expect(success_sim.run).to be_a(SimulatedRun)
    end

    it "SimulatedRun carries a Trace" do
      expect(success_sim.run.trace).to be_a(Simulator::Trace)
    end

    it "SimulatedRun carries an array of TelemetryEvent spans" do
      run = success_sim.run
      expect(run.spans).to be_an(Array)
      expect(run.spans).to all(be_a(TelemetryEvent))
    end

    it "all spans share the trace's trace_id" do
      run = success_sim.run
      expect(run.spans.map(&:trace_id).uniq).to eq([run.trace.trace_id])
    end

    it "all spans share the trace's agent_id" do
      run = success_sim.run
      expect(run.spans.map(&:agent_id).uniq).to eq([run.trace.agent_id])
    end
  end

  describe "success path (failure_rate: 0.0)" do
    subject(:run) { success_sim.run }

    it "finalizes trace status to 'success'" do
      expect(run.trace.status).to eq("success")
    end

    it "produces exactly 7 spans" do
      expect(run.spans.length).to eq(7)
    end

    it "does not include an error span" do
      expect(run.spans.map(&:span_type)).not_to include("error")
    end

    it "run_completed metadata status is 'success'" do
      completed = run.spans.find { |s| s.span_type == "run_completed" }
      expect(completed.metadata["status"]).to eq("success")
    end
  end

  describe "failure path (failure_rate: 1.0)" do
    subject(:run) { failure_sim.run }

    it "finalizes trace status to 'error'" do
      expect(run.trace.status).to eq("error")
    end

    it "produces exactly 8 spans" do
      expect(run.spans.length).to eq(8)
    end

    it "includes an error span" do
      expect(run.spans.map(&:span_type)).to include("error")
    end

    it "error span has span_id 's8'" do
      error = run.spans.find { |s| s.span_type == "error" }
      expect(error.span_id).to eq("s8")
    end

    it "error span is parented to s6 (decision)" do
      error = run.spans.find { |s| s.span_type == "error" }
      expect(error.parent_span_id).to eq("s6")
    end

    it "run_completed metadata status is 'error'" do
      completed = run.spans.find { |s| s.span_type == "run_completed" }
      expect(completed.metadata["status"]).to eq("error")
    end

    it "error span appears before run_completed in the sequence" do
      types = run.spans.map(&:span_type)
      expect(types.index("error")).to be < types.index("run_completed")
    end
  end

  describe "determinism" do
    it "produces identical runs for the same seed" do
      run_a = AgentSimulator.new(seed: 7).run
      run_b = AgentSimulator.new(seed: 7).run
      expect(run_a.trace).to eq(run_b.trace)
      expect(run_a.spans).to eq(run_b.spans)
    end

    it "produces different runs for different seeds" do
      run_a = AgentSimulator.new(seed: 1).run
      run_b = AgentSimulator.new(seed: 2).run
      expect(run_a.trace.trace_id).not_to eq(run_b.trace.trace_id)
    end
  end

  describe "overrides" do
    it "passes agent_id through to the trace" do
      run = success_sim.run(agent_id: "monitoring-agent")
      expect(run.trace.agent_id).to eq("monitoring-agent")
    end

    it "passes task_name through to the trace" do
      run = success_sim.run(task_name: "custom_task")
      expect(run.trace.task_name).to eq("custom_task")
    end
  end

  describe "SimulatedRun#to_json" do
    subject(:parsed) { JSON.parse(success_sim.run.to_json) }

    it "output contains 'trace' and 'spans' keys" do
      expect(parsed.keys).to match_array(%w[trace spans])
    end

    it "'spans' is an array" do
      expect(parsed["spans"]).to be_an(Array)
    end

    it "'trace' contains all expected trace fields" do
      expect(parsed["trace"].keys).to include("trace_id", "agent_id", "task_name", "start_time", "status")
    end

    it "each span in 'spans' contains all expected span fields" do
      parsed["spans"].each do |span|
        expect(span.keys).to include("trace_id", "span_id", "span_type", "timestamp", "agent_id", "metadata")
      end
    end
  end

  describe "#emit" do
    let(:output) { success_sim.emit }
    let(:lines)  { output.split("\n") }

    it "returns a String" do
      expect(output).to be_a(String)
    end

    it "produces one line per event (1 trace + 7 spans = 8 lines)" do
      expect(lines.length).to eq(8)
    end

    it "every line is valid JSON" do
      lines.each do |line|
        expect { JSON.parse(line) }.not_to raise_error
      end
    end

    it "first line is the trace record" do
      first = JSON.parse(lines.first)
      expect(first.keys).to include("trace_id", "agent_id", "task_name", "start_time", "status")
    end

    it "remaining lines are span events" do
      lines[1..].each do |line|
        event = JSON.parse(line)
        expect(event.keys).to include("span_id", "span_type", "trace_id", "metadata")
      end
    end

    it "all events share the same trace_id" do
      ids = lines.map { |l| JSON.parse(l)["trace_id"] }.uniq
      expect(ids.length).to eq(1)
    end

    it "span lines appear in sequence order (s1 through s7)" do
      span_ids = lines[1..].map { |l| JSON.parse(l)["span_id"] }
      expect(span_ids).to eq(%w[s1 s2 s3 s4 s5 s6 s7])
    end

    it "accepts the same overrides as run" do
      output = success_sim.emit(agent_id: "data-agent")
      trace  = JSON.parse(output.split("\n").first)
      expect(trace["agent_id"]).to eq("data-agent")
    end
  end
end
