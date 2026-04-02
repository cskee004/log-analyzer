require "json"

module Simulator
  # Immutable value object representing a single agent execution run.
  #
  # Fields:
  #   trace_id   — 16-char lowercase hex uniquely identifying this trace
  #   agent_id   — the agent type that performed the task
  #   task_name  — the task the agent was asked to complete
  #   start_time — ISO 8601 UTC string marking when the run began
  #   status     — one of "in_progress", "success", "error"
  Trace = Data.define(:trace_id, :agent_id, :task_name, :start_time, :status)

  Trace::VALID_STATUSES = %w[in_progress success error].freeze

  # Reopen with class syntax so that VALID_STATUSES is in the constant lookup chain.
  class Trace
    def self.build(trace_id:, agent_id:, task_name:, start_time:, status:)
      unless VALID_STATUSES.include?(status)
        raise ArgumentError, "Unknown status '#{status}'. Must be one of: #{VALID_STATUSES.join(', ')}"
      end

      new(trace_id: trace_id, agent_id: agent_id, task_name: task_name,
          start_time: start_time, status: status)
    end

    def to_json(*args) = to_h.to_json(*args)
  end
end

# Generates synthetic Trace metadata for simulated agent runs.
#
# Each agent type has a dedicated pool of realistic task names so that
# generated output is meaningful when inspected in the observability UI.
#
# Pass a seed for deterministic output (required for repeatable tests):
#   TraceGenerator.new(seed: 42).generate
class TraceGenerator
  AGENT_TYPES = %w[
    support-agent
    research-agent
    automation-agent
    triage-agent
    data-agent
    monitoring-agent
    code-agent
    notification-agent
  ].freeze

  TASK_NAMES = {
    "support-agent"      => %w[classify_customer_ticket resolve_billing_dispute escalate_to_human],
    "research-agent"     => %w[summarize_research_paper find_competitor_pricing extract_key_findings],
    "automation-agent"   => %w[sync_crm_records send_follow_up_emails generate_weekly_report],
    "triage-agent"       => %w[prioritize_incident_queue route_support_ticket assess_severity_level],
    "data-agent"         => %w[analyze_sales_trends generate_forecast_report clean_dataset],
    "monitoring-agent"   => %w[check_service_health detect_anomaly alert_on_threshold],
    "code-agent"         => %w[review_pull_request generate_unit_tests refactor_module],
    "notification-agent" => %w[send_status_update broadcast_incident_alert notify_stakeholders]
  }.freeze

  def initialize(seed: nil)
    @rng = seed ? Random.new(seed) : Random.new
  end

  # Returns a Trace with status "in_progress".
  # AgentSimulator is responsible for finalizing status to "success" or "error".
  #
  # @param agent_id  [String, nil] override agent selection
  # @param task_name [String, nil] override task name selection
  # @param start_time [Time] defaults to current UTC time
  # @return [Trace]
  def generate(agent_id: nil, task_name: nil, start_time: Time.now.utc)
    selected_agent = agent_id || AGENT_TYPES.sample(random: @rng)

    Simulator::Trace.build(
      trace_id:   generate_trace_id,
      agent_id:   selected_agent,
      task_name:  task_name || TASK_NAMES[selected_agent].sample(random: @rng),
      start_time: start_time.iso8601,
      status:     "in_progress"
    )
  end

  private

  # 8 random bytes unpacked as lowercase hex → 16-character trace ID.
  def generate_trace_id
    @rng.bytes(8).unpack1("H*")
  end
end
