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
# Security Keyword Frequency:
# - "Failed password" → 20 occurrences
# - "Invalid user" → 12 occurrences
# - "Root access" → 5 occurrences
# 
# Top Suspicious IPs:
# 1. 192.168.1.50 (10 security incidents, users: admin, guest)
# 2. 203.0.113.12 (5 security incidents, user: root)
# 
## - 'log_results' Hash(Array(Hash)) : A Hash of event types with corresponding individual events
#   {
#     event_type_0: [{event_0}, {event_1}]
#     event_type_1: [{event_0}, {event_1}]
#    }
# 

class LogAnalyzer

  def security_concerns(parsed_results)
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

  def create_table(title, rows)
    
  end
  
  def suspicious_ips(parsed_log)
    # Iterate through Error, Invalid_user, and Failed_password
    # If IP not in hash, add hash[new_IP] += 1
    # Else, hash[old_IP] += 1
    
    
    
  end
end

log_parser = LogParser.new
log = log_parser.read_log("./data/auth.log")

log_analyzer = LogAnalyzer.new
log_analyzer.security_concerns(log)

