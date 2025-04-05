require 'pry-byebug'

# LogParser Class
# This class is responsible for parsing Linux auth.log to identify security-related events such as
# error flags, authentication failures, session opening/closing, disconnects, sudo command usage, invalid
# users, and failed password attempts. It outputs structured data to help with analyzing suspicious activity.
# 
# Usage:
#   log_parser = LogParser.new
#   parsed_log = log_parser.read_log(path/to/file)
# 
# Attributes:
# - 'log_results' Hash(Array(Hash)) : A Hash of event types with corresponding individual events
#   {
#     event_type_0: [{event_0}, {event_1}]
#     event_type_1: [{event_0}, {event_1}]
#    }
# 
# Methods:
# - 'read_log' : Parses the input log lines and calls the event type parser
# - 'parse_error' : Parses lines that have the elevated flag 'error'
# - 'parse_auth_failure' : Parses lines that contain 'authentication_failure' 
# - 'parse_disconnect' : Parses lines that contain 'Disconnected'
# - 'parse_session_open' : Parses lines that contain 'session open'
# - 'parse_session_closed' : Parses lines that contain 'session closed'
# - 'parse_sudo_command' : Parses lines that contain 'PWD' 'USER' 'COMMAND'
# - 'parse_accept_event' : Parses lines that contain 'Accepted'
# - 'parse_invalid_user' : Parses lines that contain 'Invalid user'
# - 'parse_failed_password' : Parses lines that contain 'Failed password'
#
class LogParser
  
  
  @@parsed_log = 
  {
    Error: [],
    Auth_Failure: [],
    Disconnect: [],
    Session_opened: [],
    Session_closed: [],
    Sudo_command: [],
    Accepted: [],
    Invalid_user: [],
    Failed_password: []
  }

  # Parse the given auth.log file
  # The data, time, and host are parsed before calling the appropriate method
  # 
  # @param filename The location of the auth.log to be parsed
  # @return A hash containing an individual event found in auth.log
  def read_log(filename = "./data/auth.log")
    File.foreach(filename).with_index do |line, line_num|
      date = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}/)
      time = line.match(/\d{2}\:\d{2}\:\d{2}/)
      host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
      case line
      when /error/
        @@parsed_log[:Error] << parse_error(line, line_num, "Error flag" ,date[0], time[0], host[0])
      when /authentication failure/
        @@parsed_log[:Auth_Failure] << parse_auth_failure(line, line_num,"Authentication failure" ,date[0], time[0], host[0])
      when /Disconnected/
        @@parsed_log[:Disconnect] << parse_disconnect(line, line_num, "Disconnect", date[0], time[0], host[0])
      when /session opened/
        @@parsed_log[:Session_opened] << parse_session_open(line, line_num, "Session opened",date[0], time[0], host[0])
      when /session closed/
        @@parsed_log[:Session_closed] << parse_session_close(line, line_num, "Session closed" ,date[0], time[0], host[0])
      when /(PWD)*(USER)*(COMMAND)/
        @@parsed_log[:Sudo_command] << parse_sudo_command(line, line_num, "Sudo command",date[0], time[0], host[0])
      when /Accepted/
        @@parsed_log[:Accepted] << parse_accept_event(line, line_num, "Accept event",date[0], time[0], host[0])
      when /Invalid user/
        @@parsed_log[:Invalid_user] << parse_invalid_user(line, line_num, "Invalid user",date[0], time[0], host[0])
      when /Failed password/
        @@parsed_log[:Failed_password] << parse_failed_password(line, line_num, "Failed password",date[0], time[0], host[0])
      end
    end
    @@parsed_log
  end


  # Parse the given 'error' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'error' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return error_hash with meta data from event
  def parse_error(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    message = line.match(/(error)(.*?)(?=for)/)
    user = line.match(/(\w+)(?=\s+from)/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    port = line.match(/port\s(\d{5})/)
      
    pid_num = pid[1] if pid
    src_port = port[1] if port
    m = message[0].rstrip() if message
      
    error_hash = 
      {
        Line_number: line_num, 
        Type: type,
        Date: date, 
        Time: time, 
        Host: host, 
        PID: pid_num, 
        Message: m, 
        User: user[0], 
        Source_IP: src_ip[0], 
        Source_port: src_port 
      }
      
  end

  # Parse the given 'authentication failure' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'authentication failure' event
  # @param line_num A int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return auth_hash with meta data from event
  def parse_auth_failure(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    message = line.match(/(Disconnecting)(.*?)(?<=failures)/)
    pid_num = pid[1] if pid
    m = message[0].rstrip() if message

    auth_hash = 
    {
      Line_number: line_num, 
      Type: type,
      Date: date, 
      Time: time, 
      Host: host, 
      PID: pid_num, 
      Message: m, 
    }
  end

  # Parse the given 'Disconnected' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'Disconnected' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return disconnect_hash with meta data from event
  def parse_disconnect(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    port = line.match(/port\s(\d{5})/)
    pid_num = pid[1] if pid
    src_port = port[1] if port

    disconnect_hash = 
    {
      Line_number: line_num, 
      Type: type,
      Date: date, 
      Time: time, 
      Host: host, 
      PID: pid_num, 
      Source_IP: src_ip[0], 
      Source_port: src_port 
    }
  end

  # Parse the given 'session opened' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'session open' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return session_open_hash with meta data from event
  def parse_session_open(line, line_num, type, date, time, host)
    user = line.match(/(?<=user\s)(\w+)/)
    u = user[0] if user

    session_opened_hash =
    {
      Line_number: line_num, 
      Type: type,
      Date: date, 
      Time: time, 
      Host: host, 
      User: u
    }
  end

  # Parse the given 'session closed' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'session closed' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return session_close_hash with meta data from event
  def parse_session_close(line, line_num, type, date, time, host)
    user = line.match(/(?<=user\s)(\w+)/)
    u = user[0] if user

    session_closed_hash =
    {
      Line_number: line_num, 
      Type: type,
      Date: date, 
      Time: time, 
      Host: host,  
      User: u
    }
  end

  # Parse the given 'sudo command' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'sudo command' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return sudo_command_hash with meta data from event
  def parse_sudo_command(line, line_num, type, date, time, host)
    pwd = line.match(/(?<=PWD=)(.*?)(?=\s+\;)/)
    user = line.match(/(?<=USER=)(.*?)(?=\s+\;)/)
    command = line.match(/(?<=COMMAND=)(.*)/)

    sudo_command_hash = 
    {
      Line_number: line_num,
      Type: type,
      Date: date,
      Time: time, 
      Host: host,
      Directory: pwd[0],
      User: user[0],
      Command: command[0]
    }
  end

  # Parse the given 'Accepted' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'Accepted' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return accepted_hash with meta data from event
  def parse_accept_event(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    message = line.match(/Accepted \w+/)
    user = line.match(/for\s+(\S+)\s+from/)
    src_ip = line.match(/from\s+(\d{1,3}(?:\.\d{1,3}){3})/)
    port = line.match(/port\s+(\d+)/)
    key = line.match(/SHA256:([^\s]+)/)

    pid_num = pid[1] if pid
    src_port = port[1] if port
    user_name = user[1] if user
    src_address = src_ip[1] if src_ip
    fingerprint = key[1] if key
    msg = message[0] if message

    accepted_hash = 
      {
        Line_number: line_num,
        Type: type,
        Date: date,
        Time: time,
        Host: host,
        PID: pid_num,
        Message: msg,
        User: user_name,
        Source_IP: src_address,
        Source_port: src_port,
        Key: fingerprint
      }
  end

  # Parse the given 'Invalid user' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'Invalid user' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return error_hash with meta data from event
  def parse_invalid_user(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    user = line.match(/(\w+)(?=\s+from)/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    pid_num = pid[1] if pid
    
    invalid_hash = 
    {
      Line_number: line_num, 
      Type: type,
      Date: date, 
      Time: time, 
      Host: host, 
      PID: pid_num,
      User: user[0], 
      Source_IP: src_ip[0],
    }
  end

  # Parse the given 'failed password' line and return a hash representation with keyword data extracted
  # 
  # @param line string representation of the line containing 'failed password' event
  # @param line_num int representing the line number from auth.log
  # @param type string of the event type
  # @param date string containing the date of the event
  # @param time string containing the time of the event
  # @param host string containing the ip of the host machine the event happened on
  # 
  # @return error_hash with meta data from event
  def parse_failed_password(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    user = line.match(/(\w+)(?=\s+from)/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    port = line.match(/port\s(\d{5})/)
    pid_num = pid[1] if pid
    src_port = port[1] if port

    failed_hash = 
    {
      Line_number: line_num, 
      Date: date, 
      Type: type,
      Time: time, 
      Host: host, 
      PID: pid_num,
      User: user[0], 
      Source_IP: src_ip[0],
      Source_port: src_port
    }
  end
end

log_parser = LogParser.new
log = log_parser.read_log()