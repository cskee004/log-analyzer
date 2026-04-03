require "rails_helper"

RSpec.describe SimulatorSeeder do
  describe ".call" do
    it "creates the requested number of traces and their spans" do
      expect { SimulatorSeeder.call(count: 3) }
        .to change(Trace, :count).by(3)
        .and change(Span, :count).by_at_least(3)
    end

    it "returns a Result with traces_created count and empty errors on success" do
      result = SimulatorSeeder.call(count: 2)
      expect(result.traces_created).to eq(2)
      expect(result.errors).to be_empty
    end

    it "uses DEFAULT_COUNT when no count given" do
      expect { SimulatorSeeder.call }
        .to change(Trace, :count).by(SimulatorSeeder::DEFAULT_COUNT)
    end

    it "records errors and continues when TelemetryIngester raises" do
      call_count = 0
      allow(TelemetryIngester).to receive(:call) do
        call_count += 1
        raise TelemetryIngester::Error, "boom" if call_count == 2
      end

      result = SimulatorSeeder.call(count: 3)
      expect(result.traces_created).to eq(2)
      expect(result.errors).to eq(["boom"])
    end
  end
end
