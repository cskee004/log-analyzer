require "rails_helper"

RSpec.describe ApiKey, type: :model do
  describe "token generation" do
    it "auto-generates a token on create" do
      key = ApiKey.create!
      expect(key.token).to be_present
    end

    it "generates a unique token per record" do
      key_a = ApiKey.create!
      key_b = ApiKey.create!
      expect(key_a.token).not_to eq(key_b.token)
    end

    it "does not overwrite an existing token on save" do
      key = ApiKey.create!
      original = key.token
      key.update!(agent_type: "support-agent")
      expect(key.reload.token).to eq(original)
    end
  end

  describe "validations" do
    it "requires a token" do
      key = ApiKey.new
      key.token = nil
      expect(key).not_to be_valid
    end

    it "requires token uniqueness" do
      key_a = ApiKey.create!
      key_b = ApiKey.new(token: key_a.token)
      expect(key_b).not_to be_valid
    end

    it "requires active to be boolean" do
      expect(ApiKey.new(active: nil)).not_to be_valid
    end
  end

  describe "defaults" do
    it "is active by default" do
      expect(ApiKey.create!).to be_active
    end
  end

  describe ".active scope" do
    it "returns only active keys" do
      active = ApiKey.create!(active: true)
      ApiKey.create!(active: false)
      expect(ApiKey.active).to contain_exactly(active)
    end
  end

  describe ".authenticate" do
    it "returns the matching active key" do
      key = ApiKey.create!
      expect(ApiKey.authenticate(key.token)).to eq(key)
    end

    it "returns nil for an unknown token" do
      expect(ApiKey.authenticate("notarealtoken")).to be_nil
    end

    it "returns nil for an inactive key" do
      key = ApiKey.create!(active: false)
      expect(ApiKey.authenticate(key.token)).to be_nil
    end
  end
end
