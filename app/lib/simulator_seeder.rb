# Generates N synthetic agent runs using AgentSimulator and persists each via
# TelemetryIngester. Intended for development/debugging only.
#
# Usage:
#   result = SimulatorSeeder.call(count: 10)
#   result.traces_created  # => 10
#   result.errors          # => []
class SimulatorSeeder
  DEFAULT_COUNT = 10

  Result = Data.define(:traces_created, :errors)

  def self.call(count: DEFAULT_COUNT)
    new(count: count).call
  end

  def initialize(count: DEFAULT_COUNT)
    @count = count
    require Rails.root.join("simulator/agent_simulator")
  end

  def call
    traces_created = 0
    errors = []

    @count.times do
      ndjson = AgentSimulator.new.emit
      TelemetryIngester.call(ndjson)
      traces_created += 1
    rescue TelemetryIngester::Error => e
      errors << e.message
    end

    Result.new(traces_created: traces_created, errors: errors)
  end
end
