require

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
  :Log_level,
  :Invalid_user,
  :Target,
  :Source_IP,
  :Source_port,
  :SSH_protocol
]

# This method reads from the given file path. If a file is not given, then read_log uses default file located in the data directory.
# If line contains any of the log level keywords, then call parse_string with the single line and line number
def read_log(filename = "./data/auth.log")
  File.foreach(filename).with_index do |line, line_num| if line.include?('error') then parse_line(line, line_num)
  end
end
end


# 3903: Mar 31 10:36:28 ip-10-77-20-248 sshd[19551]: error: maximum authentication attempts exceeded for root from 122.191.89.89 port 37753 ssh2 [preauth]
# 3932: Mar 31 11:06:50 ip-10-77-20-248 sshd[19710]: error: maximum authentication attempts exceeded for invalid user ajay from 42.184.142.151 port 47882 ssh2 [preauth]
def parse_line(line, line_num)
  puts line_num
  puts line
end

read_log()