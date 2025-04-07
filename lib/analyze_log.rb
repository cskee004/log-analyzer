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

  def security_keyword_freq(parsed_log)
    rows = []
    
    parsed_log.each do |key, value|
      rows << [key.to_s, value.length] 
    end
    
    table = Terminal::Table.new :title => "Security Keyword Frequency" , :headings => ['Word', 'Occurrences'], :rows => rows
    puts table
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
log_analyzer.security_keyword_freq(log)
log_analyzer.suspicious_ips(log)
