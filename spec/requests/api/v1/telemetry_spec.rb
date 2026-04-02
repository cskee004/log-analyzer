require "rails_helper"

RSpec.describe "POST /api/v1/telemetry", type: :request do
  let(:api_key) { ApiKey.create! }

  def auth_headers
    { "Authorization" => "Bearer #{api_key.token}", "Content-Type" => "text/plain" }
  end

  def trace_line(overrides = {})
    {
      "trace_id"   => "a1b2c3d4e5f6a7b8",
      "agent_id"   => "support-agent",
      "task_name"  => "classify_customer_ticket",
      "start_time" => "2026-04-02T12:00:00Z",
      "status"     => "success"
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

  context "with a valid token and well-formed payload" do
    it "returns 201 with trace_id and spans_ingested" do
      post "/api/v1/telemetry", params: valid_ndjson, headers: auth_headers
      expect(response).to have_http_status(:created)
      body = JSON.parse(response.body)
      expect(body["trace_id"]).to eq("a1b2c3d4e5f6a7b8")
      expect(body["spans_ingested"]).to eq(1)
    end

    it "persists the trace to the database" do
      expect {
        post "/api/v1/telemetry", params: valid_ndjson, headers: auth_headers
      }.to change { Trace.count }.by(1)
    end

    it "persists the spans to the database" do
      expect {
        post "/api/v1/telemetry", params: valid_ndjson, headers: auth_headers
      }.to change { Span.count }.by(1)
    end
  end

  context "without an Authorization header" do
    it "returns 401" do
      post "/api/v1/telemetry", params: valid_ndjson,
           headers: { "Content-Type" => "text/plain" }
      expect(response).to have_http_status(:unauthorized)
    end
  end

  context "with an invalid token" do
    it "returns 401" do
      post "/api/v1/telemetry", params: valid_ndjson,
           headers: { "Authorization" => "Bearer badtoken", "Content-Type" => "text/plain" }
      expect(response).to have_http_status(:unauthorized)
    end
  end

  context "with a malformed payload" do
    it "returns 422 for invalid JSON" do
      post "/api/v1/telemetry", params: "not json\nmore garbage", headers: auth_headers
      expect(response).to have_http_status(:unprocessable_content)
      expect(JSON.parse(response.body)["error"]).to be_present
    end

    it "returns 422 for an empty body" do
      post "/api/v1/telemetry", params: "", headers: auth_headers
      expect(response).to have_http_status(:unprocessable_content)
    end

    it "returns 422 for an invalid span_type" do
      bad = [trace_line, span_line(span_type: "not_a_real_type")].join("\n")
      post "/api/v1/telemetry", params: bad, headers: auth_headers
      expect(response).to have_http_status(:unprocessable_content)
    end
  end
end
