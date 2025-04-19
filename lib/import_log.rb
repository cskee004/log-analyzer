require_relative 'preprocess_log'
require_relative 'analyze_log'

# LogImporter Class
#
# Usage:
#
# Attributes:
# - 
# Methods:
# - 

class LogImporter
  def initialize
    @event_types = %i[error auth_failure disconnect session_opened session_closed sudo_command accepted_publickey
    accepted_password invalid_user failed_password]
  end

  def import_event(log)
    @event_types.each do |symbol|
      event_batch = []
      log[symbol].select { |event| event }.each do |event|
        event_batch << event
      end
      Event.insert_all(event_batch)
    end
  end

  def clear_table
    Event.delete_all
  end
end
