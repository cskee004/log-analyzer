require_relative 'log_parser'
require_relative 'log_file_analyzer'

# LogUtility Class
# This class is responsible for anything data related for the web interface. 
# 
# Usage:
#   log_utility = LogUtility.new
#   results =  log_utility.validate_file(auth.log)
#   log_utility.POST_events(results)
#   data = log_file_analyzer.events_by_hour(results)
#   log_utility.format_for_apexcharts(data)
#   
# Attributes:
# - 'event_types' array : collection of event type symbols to control loops
# 
# Methods:
# - 'POST_events' : Inserts batch of event type from the parsed log into the Events model. 
# - 'DELETE_events' : Helper method to clear Events model
# - 'validate_file' : Validates the upload file for extension, contents, and size.
# - 'format_for_apexcharts' : Helper method to format the given dataset for plotting

class LogUtility
  def initialize
    @event_types = %i[error auth_failure disconnect session_opened session_closed sudo_command accepted_publickey
    accepted_password invalid_user failed_password]
  end

  # Inserts by the event_type into the Event model
  #
  # @param parsed_log hash containing meta data for each event type
  # 
  def POST_events(parsed_log)
    @event_types.each do |symbol|
      event_batch = []
      parsed_log[symbol].select { |event| event }.each do |event|
        event_batch << event
      end
      Event.insert_all(event_batch)
    end
  end

  def DELETE_events
    Event.delete_all
  end

  # Ensures the uploaded file is valid before the parsing process. 
  # 
  # @params uploaded_file - the users submitted file 
  # @returns array - boolean value and a response message 
  def validate_file(uploaded_file)
    allowed_types = ['application/octet-stream']
    max_size = 2 * 1024 * 1024
    filename = /^auth.*log$/
    
    unless allowed_types.include?(uploaded_file.content_type)
      return [false, "Content type failed: #{uploaded_file.content_type}"]
    end

    unless file.original_filename =~ filename
      return [false, "Filename failed: #{uploaded_file.original_filename}"]
    end
  
    if file.size >= max_size
      return [false, "File size too big: #{uploaded_file.size} bytes"]
    end

    [true, "All checks passed"]
  end

  # Formats the given data_hash so it can be used with apexcharts
  # 
  # @param data_hash - a hash returned from one of the log_file_analyzer methods
  # @return results - an array containing series name and data
  def format_for_apexcharts(data_hash)
    results = []
    data_hash.each do |key, value|
      results << {name: key.to_s, data: value}
    end
    results
  end
end
