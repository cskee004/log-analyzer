require 'pry-byebug'
require 'terminal-table'
require_relative 'preprocess_log'


# Metrics
# 
# - Error :  
# - Auth_failure :
# - Disconnect
# - Session_opened
# - Session_closed
# - Sudo_command : Top users using sudo commands 
# - Accepted : Time + type + IP
# - Invalid_user : Time + IP
# - Failed_password : Time + IP + User
#
# Top Suspicious IPs:
# 1. 192.168.1.50 (10 security incidents, users: admin, guest)
# 2. 203.0.113.12 (5 security incidents, user: root)
# 
# LogAnalyzer Class
# This class is responsible for analyzing security related events found in parsed_results. This class makes the following assumptions...
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
# Usage
# log_analyzer = LogAnalyzer.new
# log_analyzer.get_summary(log)

class LogAnalyzer

  def get_summary(parsed_results)
    high_rows = []
    med_rows = []
    ops_rows = []
    
    high_rows << ["Error Flags", parsed_results[:Error].length]
    high_rows << ["Authentication failures", parsed_results[:Auth_failure].length]
    high_rows << ["Invalid users", parsed_results[:Invalid_user].length]
    high_rows << ["Failed password attempts", parsed_results[:Failed_password].length]

    med_rows << ["Disconnects", parsed_results[:Disconnect].length]
    med_rows << ["Accepted publickey", parsed_results[:Accepted_publickey].length]
    med_rows << ["Accepted password", parsed_results[:Accepted_password].length]
    med_rows << ["Session Opens", parsed_results[:Session_opened].length]
    med_rows << ["Session Closes", parsed_results[:Session_closed].length]

    ops_rows << ["Sudo usage", parsed_results[:Sudo_command].length]
    
    high_table = Terminal::Table.new :title => "High Security Concerns" , :headings => ['Event Type', 'Occurrences'], :rows => high_rows
    med_table = Terminal::Table.new :title => "Medium Security Concerns" , :headings => ['Event Type', 'Occurrences'], :rows => med_rows
    ops_table = Terminal::Table.new :title => "Operational Monitoring" , :headings => ['Event Type', 'Occurrences'], :rows => ops_rows

    puts high_table
    puts med_table 
    puts ops_table   


  end

  def suspicious_ips(parsed_log)
    # Create empty hash
    # Loop through parsed logs, filtering only high security events
    #   Get source ip from event
    #   If ip does not exist in hash, create new array with the event hash 
    #   If ip does exist in hash, append array with event hash
    event_types = [:Error, :Invalid_user, :Failed_password]
    result = {}
   
    event_types.each do |symbol|
      parsed_log[symbol].select { |event| event }.each do |event|
          result[event[:Source_IP]] ||= [] # Set result[ip] to new empty array if nil or doesn't exist
          result[event[:Source_IP]] << event # Add event to array
      end 
    end
    # result.each {|key, value| puts "IP: #{key}, #{value.length} occurrences"}
  end
end