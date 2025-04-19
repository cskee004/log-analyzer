require_relative 'preprocess_log'

# LogImporter Class
#
# Usage:
#
# Attributes:
# - 
# Methods:
# - 


class LogImporter
  def initialize(parser)
    @parser = parser
    @event_types = %i[Error Auth_failure Disconnect Session_opened Session_closed Sudo_command Accepted_publickey
    Accepted_password Invalid_user Failed_password]
  end

  
  def import_event(log)
    @event_types.each do |symbol|
      log[symbol].select { |event| event }.each do |event|
        export_event(event)
      end
    end
  end

  def export_event(event)
    new_event = Event.new(event_type: event[:Type], date: event[:Date], time: event[:Time], pid: event[:PID], message: event[:Message], 
              user: event[:User], source_ip: event[:Source_IP], source_port: event[:Source_port], directory: event[:Directory],
              command: event[:Command], key: event[:Key], host: event[:Host])
    new_event.save
    puts new_event.errors.full_messages
  end

  def clear_table
    Event.delete_all
  end
end

log_parser = LogParser.new
log = log_parser.read_log('./data/auth-test.log')

log_importer = LogImporter.new(log_parser)
log_importer.import_event(log)
