require 'pry-byebug'


# This method reads from the given file path. If a file is not given, then read_log uses default file located in the data directory.
# If a single line contains any of the log level keywords, then call parse_string with the single line and line number
def read_log(filename = "./data/auth.log")
  File.foreach(filename).with_index do |line, line_num|
    case line
    when /error/
      parse_error(line, line_num)
    when /authentication failure/
      parse_auth_failure(line, line_num)
    when /Disconnected/
      parse_disconnect(line, line_num)
    when /session opened/
      parse_session_open(line, line_num)
    when /session closed/
      parse_session_close(line, line_num)
    when /(PWD)*(USER)*(COMMAND)/
      parse_sudo_command(line, line_num)
    when /Accepted/
      parse_accept_event(line, line_num)
    end
  end
end



def parse_error(line, line_num)
  
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  message = line.match(/(error)(.*?)(?=for)/)
  user = line.match(/(\w+)(?=\s+from)/)
  src_ip = line.match(/\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}/)
  port = line.match(/port\s(\d{5})/)
  
  pid_num = pid[1] if pid
  src_port = port[1] if port
  m = message[0].rstrip() if message
  
  # log_pattern = /(^\D{4}\d{2}) (\d{2}\:\d{2}\:\d{2}) (\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}) (\[(\d+)\]) ((error)(.*?)(?=for)) ((\w+)(?=\s+from)) (\d{2}\.\d{3}\.\d{3}\.\d{3}) (port\s(\d{5}))/
  
  error_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: m, 
    User: user[0], 
    Source_IP: src_ip[0], 
    Source_port: src_port 
  }
  
end

def parse_auth_failure(line, line_num)
  
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  message = line.match(/(Disconnecting)(.*?)(?<=failures)/)
  auth_stage = line.match(/\[(\D+)\]/)

  pid_num = pid[1] if pid
  m = message[0].rstrip() if message

  auth_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: m, 
    Stage: auth_stage[1]
  }
end

def parse_disconnect(line, line_num)
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  message = line.match(/(Disconnected)(.*?)(?=from)/)
  user = line.match(/(\w+)(?=\s+from)/)
  src_ip = line.match(/\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}/)
  port = line.match(/port\s(\d{5})/)
  
  pid_num = pid[1] if pid
  src_port = port[1] if port
  m = message[0].rstrip() if message

  disconnect_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: m,  
    Source_IP: src_ip[0], 
    Source_port: src_port 
  }
end

def parse_session_open(line, line_num) #11
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  message = line.match(/(sudo:)(.*?)(?=for)/)
  user = line.match(/(?<=user\s)(\w+)/)

  m = message[0].rstrip() if message
  u = user[0] if user

  session_open_hash =
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0],  
    Message: m, 
    User: u
  }
end

def parse_session_close(line, line_num)
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  message = line.match(/(sudo:)(.*?)(?=for)/)
  user = line.match(/(?<=user\s)(\w+)/)

  m = message[0].rstrip() if message
  u = user[0] if user

  session_open_hash =
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0],  
    Message: m, 
    User: u
  }
end

def parse_sudo_command(line, line_num)
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pwd = line.match(/(?<=PWD=)(.*?)(?=\s+\;)/)
  user = line.match(/(?<=USER=)(.*?)(?=\s+\;)/)
  command = line.match(/(?<=COMMAND=)(.*)/)

  sudo_command_hash = 
  {
    Line_number: line_num,
    Date: date[0],
    Time: time[0], 
    Host: host[0],
    Directory: pwd[0],
    User: user[0],
    Command: command[0]
  }
end

def parse_accept_event(line, line_num)
  
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  message = line.match(/(Accepted)(.*?)(?=\s+for)/)
  user = line.match(/(\w+)(?=\s+from)/)
  src_ip = line.match(/\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}/)
  port = line.match(/port\s(\d{5})/)
  key = line.match(/(?<=SHA256:)(\w+)/)
  
  pid_num = pid[1] if pid
  src_port = port[1] if port
  m = message[0].rstrip() if message
  
  error_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: m, 
    User: user[0], 
    Source_IP: src_ip[0], 
    Source_port: src_port,
    Key: key[0]
  }
end

def parse_invalid_user(line, line_num)
  
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  message = "Invalid user"
  user = line.match(/(\w+)(?=\s+from)/)
  src_ip = line.match(/\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}/)
  
  pid_num = pid[1] if pid
  
  invalid_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: message, 
    User: user[0], 
    Source_IP: src_ip[0],
  }
end

def parse_failed_password(line, line_num)
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  message = "Failed password"
  user = line.match(/(\w+)(?=\s+from)/)
  src_ip = line.match(/\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}/)
  port = line.match(/port\s(\d{5})/)

  pid_num = pid[1] if pid
  src_port = port[1] if port

  failed_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: message, 
    User: user[0], 
    Source_IP: src_ip[0],
    Source_port: src_port
  }
end

read_log("./data/auth-test.log")