require 'pry-byebug'
require 'terminal-table'
require_relative 'preprocess_log'

# LogAnalyzer Class
# This class is responsible for analyzing security related events found in parsed_log. This class makes the following assumptions...
# High Security Concerns:
# - Error Flags: Repeated errors could indicate malicious network patterns, suspicious login hours, or abnormal sequences of actions
# - Authentication failures: Many failures in a short time could indicate brute-force or credential stuffing attacks
# - Invalid user: Usernames that don't exist could indicate brute-force attempts
# - Failed password: The wrong password could be a legitimate error by the user or brute-force attempts
# Medium Security Concerns:
# - Disconnects: Abnormal disconnects could indicate session hijacking or instability due to network load
# - Accepted publickey and passwords: Logins from strange IPs using a password
# - Session opens/closes: Unusual session durations, late-night activity, or sessions without proper closure could indicate system compromise
# Operation Monitoring:
# - Sudo commands: Sudo usage from non-admins could indicate insider threats or privilege abuse
#
# Usage:
#   log_analyzer = LogAnalyzer.new
#   log_analyzer.get_summary(log)
#
# Attributes:
#
# Methods:
#   - 'get_summary' : Prints a table for each severity level (High, Medium, regular ops)
#   - 'suspicious_ips' : Analyzes the parsed results by connecting IP addresses to high security events
#   - 'events_by_hour' : Analyzes the hours that each event took place
#   - 'events_by_day' :

class LogAnalyzer
  def initialize
    @event_types = [
      :Error, :Auth_failure, 
      :Disconnect, :Session_opened, 
      :Session_closed, :Sudo_command, 
      :Accepted_publickey, :Accepted_password, 
      :Invalid_user, :Failed_password
    ]
    @high_events = [:Error, :Invalid_user, :Failed_password]
    @med_events  = [:Disconnect, :Accepted_publickey, :Accepted_password, :Session_opened, :Session_closed]
    @low_events  = [:Sudo_command]
    
  end

  # Prints to console results sorted into severity type along with how many occurrences 
  # 
  # @param parsed_log hash containing meta data for each event type
  def get_summary(parsed_log)
    high_rows = []
    med_rows = []
    ops_rows = []
    
    high_rows << ["Error Flags", parsed_log[:Error].length]
    high_rows << ["Authentication failures", parsed_log[:Auth_failure].length]
    high_rows << ["Invalid users", parsed_log[:Invalid_user].length]
    high_rows << ["Failed password attempts", parsed_log[:Failed_password].length]

    med_rows << ["Disconnects", parsed_log[:Disconnect].length]
    med_rows << ["Accepted publickey", parsed_log[:Accepted_publickey].length]
    med_rows << ["Accepted password", parsed_log[:Accepted_password].length]
    med_rows << ["Session Opens", parsed_log[:Session_opened].length]
    med_rows << ["Session Closes", parsed_log[:Session_closed].length]

    ops_rows << ["Sudo usage", parsed_log[:Sudo_command].length]
    
    high_table = Terminal::Table.new :title => "High Security Concerns" , :headings => ['Event Type', 'Occurrences'], :rows => high_rows
    med_table = Terminal::Table.new :title => "Medium Security Concerns" , :headings => ['Event Type', 'Occurrences'], :rows => med_rows
    ops_table = Terminal::Table.new :title => "Operational Monitoring" , :headings => ['Event Type', 'Occurrences'], :rows => ops_rows

    puts high_table
    puts med_table 
    puts ops_table   
  end

  # Collects unique IP addresses and their associated high security events
  #       
  # @param parsed_log hash containing meta data for each event type
  # @return A hash of unique IP addresses with associated events for that specific IP 
  def suspicious_ips(parsed_log)
    result = {}
    
    @high_events.each do |symbol|
      parsed_log[symbol].select { |event| event }.each do |event|    
        result[event[:Source_IP]] ||= [] # Set result[ip] to new empty array if nil or doesn't exist
        result[event[:Source_IP]] << event # Add event to array
      end 
    end
    result
  end

  # Finds the number of occurrences of each type of event by the hour
  # 
  # @param parsed_log hash containing meta data for each event type 
  # @return A hash of event types with number of occurrences for each hour that event took place
  def events_by_hour(parsed_log)
    result = {}
    
    @event_types.each do |symbol|
      parsed_log[symbol].select { |event| event}.each do |event|
        time = event[:Time].split(":")
        hour = time[0].to_sym
        result[symbol] ||= {}
        result[symbol][hour] ||= 0
        result[symbol][hour] += 1
      end
    end
    result
  end

  def events_by_day(parsed_log)

  end


end