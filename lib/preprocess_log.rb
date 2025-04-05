require 'pry-byebug'

class LogParser
  
def read_log(filename = "./data/auth.log")
  File.foreach(filename).with_index do |line, line_num|
    date = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}/)
    time = line.match(/\d{2}\:\d{2}\:\d{2}/)
    host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
    case line
    when /error/
      puts parse_error(line, line_num, "Error flag" ,date[0], time[0], host[0])
    when /authentication failure/
      puts parse_auth_failure(line, line_num,"Authentication failure" ,date[0], time[0], host[0])
    when /Disconnected/
      puts parse_disconnect(line, line_num, "Disconnect", date[0], time[0], host[0])
    when /session opened/
      puts parse_session_open(line, line_num, "Session opened",date[0], time[0], host[0])
    when /session closed/
      puts parse_session_close(line, line_num, "Session closed" ,date[0], time[0], host[0])
    when /(PWD)*(USER)*(COMMAND)/
      puts parse_sudo_command(line, line_num, "Sudo command",date[0], time[0], host[0])
    when /Accepted/
      puts parse_accept_event(line, line_num, "Accept event",date[0], time[0], host[0])
    when /Invalid user/
      puts parse_invalid_user(line, line_num, "Invalid user",date[0], time[0], host[0])
    when /Failed password/
      puts parse_failed_password(line, line_num, "Failed password",date[0], time[0], host[0])
    end
  end
end


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

def parse_session_open(line, line_num, type, date, time, host)
  user = line.match(/(?<=user\s)(\w+)/)
  u = user[0] if user

  session_open_hash =
  {
    Line_number: line_num, 
    Type: type,
    Date: date, 
    Time: time, 
    Host: host, 
    User: u
  }
end

def parse_session_close(line, line_num, type, date, time, host)
  user = line.match(/(?<=user\s)(\w+)/)
  u = user[0] if user

  session_open_hash =
  {
    Line_number: line_num, 
    Type: type,
    Date: date, 
    Time: time, 
    Host: host,  
    User: u
  }
end

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
log_parser.read_log()