# Example of a suspicous message found in auth.log
# 15:59:42 ip-10-77-20-248 sshd[3242]: error: maximum authentication attempts exceeded for root from 186.128.152.44 port 34605 ssh2 [preauth]
# ip-10-77-20-248 = Hostname
# sshd[3242] = sshd is logging the event for PID 3242
# error = log level
# for root = target user account
# from 186.128.152.44 = source ip
# port 34605 = source port on attackers machine
# ssh2 = SSH protocol used
# [preauth] = log entry occurred before authentication

test_string = "Mar 28 07:36:32 ip-10-77-20-248 sshd[22419]: error: maximum authentication attempts exceeded for invalid user admin from 14.185.87.49 port 47825 ssh2 [preauth]"

log_levels = 
[
  "emerg",
  "alert",
  "crit",
  "error",
  "warn",
  "notice",
  "info",
  "debug"
]
meta_data = 
[
  :Line_number,
  :Date,
  :Time,
  :Host,
  :PID,
  :Message,
  :User,
  :Source_IP,
  :Source_port
]

# This method reads from the given file path. If a file is not given, then read_log uses default file located in the data directory.
# If line contains any of the log level keywords, then call parse_string with the single line and line number
def read_log(filename = "./data/auth.log")
  File.foreach(filename).with_index do |line, line_num| if line.include?('error') then parse_error_line(line, line_num)
  end
end
end



def parse_error_line(line, line_num)
  
  date = line.match(/^\D{4}\d{2}/)
  time = line.match(/\d{2}\:\d{2}\:\d{2}/)
  host = line.match(/\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}/)
  pid = line.match(/\[(\d+)\]/)
  pid_num = pid[1] if pid
  message = line.match(/(error)(.*?)(?=for)/)
  user = line.match(/(\w+)(?=\s+from)/)
  src_ip = line.match(/\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}/)
  puts src_ip
  port = line.match(/port\s(\d{5})/)
  src_port = port[1] if port

  log_pattern = /(^\D{4}\d{2}) (\d{2}\:\d{2}\:\d{2}) (\D{3}\d{2}\-\d{2}\-\d{2}-\d{3}) (\[(\d+)\]) ((error)(.*?)(?=for)) ((\w+)(?=\s+from)) (\d{2}\.\d{3}\.\d{3}\.\d{3}) (port\s(\d{5}))/
  
  line_hash = 
  {
    Line_number: line_num, 
    Date: date[0], 
    Time: time[0], 
    Host: host[0], 
    PID: pid_num, 
    Message: message[0], 
    User: user[0], 
    Source_IP: src_ip[0], 
    Source_port: src_port 
  }
  
end

read_log("./data/auth-test.log")