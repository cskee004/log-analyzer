require "rails_helper"

RSpec.describe "POST /api/v1/keys", type: :request do
  def post_keys(body = {})
    post "/api/v1/keys",
         params:  body.to_json,
         headers: { "Content-Type" => "application/json" }
  end

  it "returns 201 with a token and message" do
    post_keys(agent_type: "support-agent")
    expect(response).to have_http_status(:created)
    body = JSON.parse(response.body)
    expect(body["token"]).to be_present
    expect(body["agent_type"]).to eq("support-agent")
    expect(body["message"]).to be_present
  end

  it "creates an ApiKey record" do
    expect { post_keys(agent_type: "code-agent") }.to change { ApiKey.count }.by(1)
  end

  it "works without an agent_type" do
    post_keys
    expect(response).to have_http_status(:created)
    body = JSON.parse(response.body)
    expect(body["token"]).to be_present
    expect(body["agent_type"]).to be_nil
  end

  it "returns a unique token on each call" do
    post_keys
    token_a = JSON.parse(response.body)["token"]
    post_keys
    token_b = JSON.parse(response.body)["token"]
    expect(token_a).not_to eq(token_b)
  end

  it "returned token is immediately usable for authentication" do
    post_keys(agent_type: "monitoring-agent")
    token = JSON.parse(response.body)["token"]

    post "/api/v1/auth/token",
         params:  { token: token }.to_json,
         headers: { "Content-Type" => "application/json" }

    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)["valid"]).to be true
  end
end
