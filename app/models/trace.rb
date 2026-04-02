class Trace < ApplicationRecord
  AGENT_TYPES = %w[
    support-agent research-agent automation-agent triage-agent
    data-agent monitoring-agent code-agent notification-agent
  ].freeze

  enum :status, { in_progress: 0, success: 1, error: 2 }

  has_many :spans, foreign_key: :trace_id, primary_key: :trace_id,
                   inverse_of: :trace, dependent: :destroy

  validates :trace_id,   presence: true, uniqueness: true, length: { is: 16 }
  validates :agent_id,   presence: true, inclusion: { in: AGENT_TYPES }
  validates :task_name,  presence: true
  validates :start_time, presence: true
  validates :status,     presence: true
end
