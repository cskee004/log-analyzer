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
# 1. 192.168.1.50 (10 failed attempts, users: admin, guest)
# 2. 203.0.113.12 (5 failed attempts, user: root)
# 

class LogAnalyzer

  def security_keyword_freq(parsed_log)
    rows = []
    
    parsed_log.each do |key, value|
      rows << [key, value.length] 
    end
    
    table = Terminal::Table.new :title => "Security Keyword Frequency" , :headings => ['Word', 'Occurrences'], :rows => rows
    puts table
  end
  
  def suspicious_ips(parsed_log)
    
  end
end

log_parser = LogParser.new
log = log_parser.read_log("./data/auth.log")

log_analyzer = LogAnalyzer.new
log_analyzer.security_keyword_freq(log)
