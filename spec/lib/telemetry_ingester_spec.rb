require "rails_helper"

RSpec.describe TelemetryIngester do
  def trace_line(overrides = {})
    {
      "trace_id"  => "a1b2c3d4e5f6a7b8",
      "agent_id"  => "support-agent",
      "task_name" => "classify_customer_ticket",
      "start_time" => "2026-04-02T12:00:00Z",
      "status"    => "success"
    }.merge(overrides).to_json
  end

  def span_line(overrides = {})
    {
      "trace_id"       => "a1b2c3d4e5f6a7b8",
      "span_id"        => "s1",
      "parent_span_id" => nil,
      "span_type"      => "agent_run_started",
      "timestamp"      => "2026-04-02T12:00:01Z",
      "agent_id"       => "support-agent",
      "metadata"       => { "task" => "classify_customer_ticket" }
    }.merge(overrides).to_json
  end

  def valid_ndjson
    [trace_line, span_line].join("\n")
  end

  describe ".call" do
    it "persists the trace and returns trace_id and spans_ingested" do
      result = described_class.call(valid_ndjson)
      expect(result[:trace_id]).to eq("a1b2c3d4e5f6a7b8")
      expect(result[:spans_ingested]).to eq(1)
      expect(Trace.find_by(trace_id: "a1b2c3d4e5f6a7b8")).to be_present
      expect(Span.where(trace_id: "a1b2c3d4e5f6a7b8").count).to eq(1)
    end

    it "persists multiple spans" do
      ndjson = [
        trace_line,
        span_line(span_id: "s1", span_type: "agent_run_started"),
        span_line(span_id: "s2", span_type: "model_call",
                  parent_span_id: "s1",
                  metadata: { "model_name" => "claude-sonnet-4-6", "prompt_tokens" => 100 })
      ].join("\n")

      result = described_class.call(ndjson)
      expect(result[:spans_ingested]).to eq(2)
    end

    it "ignores blank lines" do
      ndjson = "\n#{trace_line}\n\n#{span_line}\n"
      expect { described_class.call(ndjson) }.not_to raise_error
    end

    it "raises Error on empty payload" do
      expect { described_class.call("") }
        .to raise_error(TelemetryIngester::Error, /empty/)
    end

    it "raises Error when no span lines are present" do
      expect { described_class.call(trace_line) }
        .to raise_error(TelemetryIngester::Error, /at least one span/)
    end

    it "raises Error on malformed JSON" do
      expect { described_class.call("not json\n#{span_line}") }
        .to raise_error(TelemetryIngester::Error, /invalid JSON/)
    end

    it "raises Error for an invalid span_type" do
      bad_span = span_line(span_type: "unknown_type")
      expect { described_class.call("#{trace_line}\n#{bad_span}") }
        .to raise_error(TelemetryIngester::Error)
    end

    it "rolls back the transaction if a span is invalid" do
      bad_span = span_line(span_type: "unknown_type")
      ndjson = "#{trace_line}\n#{span_line}\n#{bad_span}"
      expect {
        described_class.call(ndjson) rescue nil
      }.not_to change { Trace.count }
    end
  end
end
