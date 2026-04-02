require "rails_helper"

RSpec.describe "POST /api/v1/auth/token", type: :request do
  let(:api_key) { ApiKey.create! }

  def post_token(token)
    post "/api/v1/auth/token",
         params:  { token: token }.to_json,
         headers: { "Content-Type" => "application/json" }
  end

  context "with a valid active token" do
    it "returns 200 with valid: true" do
      post_token(api_key.token)
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)["valid"]).to be true
    end

    it "includes agent_type in the response" do
      key = ApiKey.create!(agent_type: "code-agent")
      post_token(key.token)
      expect(JSON.parse(response.body)["agent_type"]).to eq("code-agent")
    end
  end

  context "with an unknown token" do
    it "returns 401" do
      post_token("thisisnotavalidtoken")
      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body)["error"]).to be_present
    end
  end

  context "with an inactive token" do
    it "returns 401" do
      inactive = ApiKey.create!(active: false)
      post_token(inactive.token)
      expect(response).to have_http_status(:unauthorized)
    end
  end
end
