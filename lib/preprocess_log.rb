require 'date'

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
# - 'parsed_log' Hash(Array(Hash)) : A Hash of event types with corresponding individual events
#   {
#     event_type_0: [{event_0}, {event_1}]
#     event_type_1: [{event_0}, {event_1}]
#    }
# - 'start_date' string : first recorded date in the given log
# - 'end_date' string : last recorded date in the given log
# - 'date_range' array : holds the date range found in the given log
# - 'months' hash : helper for converting 3 letter month abbreviations to numerical representations
#
# Methods:
# - 'set_date_range' : helper function to build dates hash
# - 'sanitize_date' : normalizes dates
# - 'create_date_range' : creates a hash of dates keys with values of 0
# - 'get_date_range' : helper function to return date range array
# - 'read_log' : parses the input log lines and calls the event type parser
# - 'parse_error' : parses lines that have the flag 'error' event
# - 'parse_auth_failure' : parses lines that contain 'authentication_failure' event
# - 'parse_disconnect' : parses lines that contain 'Disconnected' event
# - 'parse_session_open' : parses lines that contain 'session open' event
# - 'parse_session_closed' : parses lines that contain 'session closed' event
# - 'parse_sudo_command' : parses lines that contain sudo_command usage
# - 'parse_accept_event' : parses lines that contain 'Accepted' event
# - 'parse_invalid_user' : parses lines that contain 'Invalid user' event
# - 'parse_failed_password' : parses lines that contain 'Failed password' event
#
class LogParser
  def initialize
    @parsed_log = { Error: [], Auth_failure: [], Disconnect: [], Session_opened: [], Session_closed: [],
                    Sudo_command: [], Accepted_publickey: [], Accepted_password: [], Invalid_user: [],
                    Failed_password: [] }
    @dates = {}
    @months = { 'Jan' => '1', 'Feb' => '2', 'Mar' => '3', 'Apr' => '4', 'May' => '5', 'Jun' => '6', 'Jul' => '7',
                'Aug' => '8', 'Sep' => '9', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12' }
  end

  # Reads the given file line by line. Routes lines by parsed event type
  #
  # @param filename - the location of the auth.log to be parsed
  # @return parsed_log - a hash containing an individual event found in auth.log

  def read_log(filename = "./data/auth.log")
    start_date = nil
    end_date = nil
    if File.exist?(filename) && !File.zero?(filename)
      File.foreach(filename).with_index do |line, line_num|
        start_date = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}/) if start_date.nil?

        date_stamp = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}/)
        date_string = sanitize_date(date_stamp[0])
        time = line.match(/\d{2}\:\d{2}\:\d{2}/)
        host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
        end_date = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}/)

        case line
        when /error/
          @parsed_log[:Error] << parse_error(line, line_num, 'Error flag', date_string, time[0], host[0])
        when /authentication failure/
          @parsed_log[:Auth_failure] << parse_auth_failure(line, line_num, 'Authentication failure', date_string,
                                                           time[0], host[0])
        when /Disconnected/
          @parsed_log[:Disconnect] << parse_disconnect(line, line_num, 'Disconnect', date_string, time[0], host[0])
        when /session opened/
          @parsed_log[:Session_opened] << parse_session_open(line, line_num, 'Session opened', date_string, time[0],
                                                             host[0])
        when /session closed/
          @parsed_log[:Session_closed] << parse_session_close(line, line_num, 'Session closed', date_string, time[0],
                                                              host[0])
        when /(PWD)*(USER)*(COMMAND)/
          @parsed_log[:Sudo_command] << parse_sudo_command(line, line_num, 'Sudo command', date_string, time[0],
                                                           host[0])
        when /Accepted publickey/
          @parsed_log[:Accepted_publickey] << parse_accept_event(line, line_num, 'Accept publickey', date_string,
                                                                 time[0], host[0])
        when /Accepted password/
          @parsed_log[:Accepted_password] << parse_accept_event(line, line_num, 'Accepted password', date_string,
                                                                time[0], host[0])
        when /Invalid user/
          @parsed_log[:Invalid_user] << parse_invalid_user(line, line_num, 'Invalid user', date_string, time[0],
                                                           host[0])
        when /Failed password/
          @parsed_log[:Failed_password] << parse_failed_password(line, line_num, 'Failed password', date_string,
                                                                 time[0], host[0])
        end
      end

    else
      puts 'File missing or empty'
    end
    set_date_range(start_date[0], end_date[0])
    @parsed_log
  end

  # Calls sanitize_date on first and last and then passes to create_date_range
  #
  # @param first string - the date from the first line of the given file
  # @param last string - the date from the last line of the given file

  def set_date_range(first, last)
    first = sanitize_date(first)
    last = sanitize_date(last)
    create_date_range(first, last)
  end

  # Converts given date into a normalized format
  #
  # @param log_date string - date
  # @returns s_date Date obj - date

  def sanitize_date(log_date)
    date = log_date.split(' ')
    calendar_month = @months.fetch(date[0])
    month = calendar_month.to_i
    day = date[1].to_i
    date_date = Date.new(2025, month, day)
    date_date.to_s
  end

  # Creates a hash of dates in the range of first last inclusive.
  #
  # @param first Date obj - date from first entry in log
  # @param last Date obj - date from the last entry in log
  # @returns hash of dates {date => count}

  def create_date_range(first, last)
    range = []

    begin_date = Date.parse(first)
    end_date = Date.parse(last)
    begin_date.step(end_date) { |date| range << date.to_s }

    @dates = range.to_h { |date| [date, 0] }
    @dates
  end

  # Helper function to return dates
  #
  # @return dates - a hash of dates
  def get_date_range
    @dates.clone
  end

  # Parse the given 'error' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'error' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
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
    m = message[0].rstrip if message

    error_hash = {  Line_number: line_num, Type: type, Date: date, Time: time, Host: host, PID: pid_num, Message: m,
                    User: user[0], Source_IP: src_ip[0], Source_port: src_port }
  end

  # Parse the given 'authentication failure' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'authentication failure' event
  # @param line_num - A int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return auth_hash with meta data from event

  def parse_auth_failure(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    message = line.match(/(Disconnecting)(.*?)(?<=failures)/)
    pid_num = pid[1] if pid
    m = message[0].rstrip() if message

    auth_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, PID: pid_num, Message: m }
  end

  # Parse the given 'Disconnected' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'Disconnected' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return disconnect_hash with meta data from event

  def parse_disconnect(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    port = line.match(/port\s(\d{5})/)
    pid_num = pid[1] if pid
    src_port = port[1] if port

    disconnect_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, PID: pid_num,
                        Source_IP: src_ip[0], Source_port: src_port }
  end

  # Parse the given 'session opened' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'session open' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return session_open_hash with meta data from event

  def parse_session_open(line, line_num, type, date, time, host)
    user = line.match(/(?<=user\s)(\w+)/)
    u = user[0] if user

    session_opened_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, User: u }
  end

  # Parse the given 'session closed' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'session closed' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return session_close_hash with meta data from event
  def parse_session_close(line, line_num, type, date, time, host)
    user = line.match(/(?<=user\s)(\w+)/)
    u = user[0] if user

    session_closed_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, User: u }
  end

  # Parse the given 'sudo command' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'sudo command' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return sudo_command_hash with meta data from event

  def parse_sudo_command(line, line_num, type, date, time, host)
    pwd = line.match(/(?<=PWD=)(.*?)(?=\s+\;)/)
    user = line.match(/(?<=USER=)(.*?)(?=\s+\;)/)
    command = line.match(/(?<=COMMAND=)(.*)/)

    sudo_command_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, Directory: pwd[0],
                          User: user[0], Command: command[0] }
  end

  # Parse the given 'Accepted' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'Accepted' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
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

    accepted_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, PID: pid_num, Message: msg,
                      User: user_name, Source_IP: src_address, Source_port: src_port, Key: fingerprint }
  end

  # Parse the given 'Invalid user' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'Invalid user' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return error_hash with meta data from event

  def parse_invalid_user(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    user = line.match(/(\w+)(?=\s+from)/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    pid_num = pid[1] if pid

    invalid_hash = {  Line_number: line_num, Type: type, Date: date, Time: time, Host: host, PID: pid_num,
                      User: user[0], Source_IP: src_ip[0] }
  end

  # Parse the given 'failed password' line and return a hash representation with keyword data extracted
  #
  # @param line - string representation of the line containing 'failed password' event
  # @param line_num - int representing the line number from auth.log
  # @param type - string of the event type
  # @param date - string containing the date of the event
  # @param time - string containing the time of the event
  # @param host - string containing the ip of the host machine the event happened on
  #
  # @return error_hash with meta data from event

  def parse_failed_password(line, line_num, type, date, time, host)
    pid = line.match(/\[(\d+)\]/)
    user = line.match(/(\w+)(?=\s+from)/)
    src_ip = line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    port = line.match(/port\s(\d{5})/)
    pid_num = pid[1] if pid
    src_port = port[1] if port

    failed_hash = { Line_number: line_num, Type: type, Date: date, Time: time, Host: host, PID: pid_num,
                    User: user[0], Source_IP: src_ip[0], Source_port: src_port }
  end
end
