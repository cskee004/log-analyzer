require_relative 'log_parser'
require_relative 'log_file_analyzer'

# LogImporter Class
#
# Usage:
#
# Attributes:
# - 
# Methods:
# - 

class Utility
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

  def validate_file(file)
    allowed_types = ['application/octet-stream']
    max_size = 2 * 1024 * 1024
    filename = /^auth.*log$/
    
    unless allowed_types.include?(file.content_type)
      return [false, "Content type failed: #{file.content_type}"]
    end

    unless file.original_filename =~ filename
      return [false, "Filename failed: #{file.original_filename}"]
    end
  
    if file.size >= max_size
      return [false, "File size too big: #{file.size} bytes"]
    end

    [true, "All checks passed"]
  end
end
