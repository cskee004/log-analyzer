require 'pry-byebug'
require 'terminal-table'
require_relative 'preprocess_log'
require 'unicode_plot'

# LogAnalyzer Class
# This class is responsible for analyzing security related events found in parsed_log. This class makes the following assumptions...
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
# Usage:
#   log_analyzer = LogAnalyzer.new
#   log_analyzer.get_summary(log)
#
# Attributes:
# - 'parser' LogParser : instance 
# - 'event_types' array : collection of event type symbols to control loops 
# - 'high_events'array : collection of high security event symbols
# - 'med_events' array : medium security symbols
# - 'low_events' array : low security symbols
# - 'login_events' array : more symbols 
# - 'months' hash : helper for converting 3 letter month abbreviations to the months numerical representation
# - 'hours' hash : helper for normalizing datasets that use hour based analysis 
#
# Methods:
# - 'plot_day_series' : Creates a visual aid for the given dataset
# - 'plot_hour_series' : Creates a visual aid for the given dataset
# - 'plot_ip_aggregate' : Creates a visual aid for the given dataset
# - 'build_date_range' : Helper function for normalizing datasets that use date based analysis 
# - 'get_summary' : Prints a table for each severity level (High, Medium, regular ops)
# - 'suspicious_ips' : Rank top 10 IPs by number of high security concerns
# - 'events_by_hour' : Finds what event type happens during each hour of the day
# - 'events_by_day' : Finds what event type happens during each day
# - 'login_patterns' : Reports when users typically log in and when failures occur
# - 'get_summary' : prints tables to the console that summarize the results from LogParser

class LogAnalyzer

  def initialize(parser)
    @parser = parser
    @event_types = [
      :Error, :Auth_failure, 
      :Disconnect, :Session_opened, 
      :Session_closed, :Sudo_command, 
      :Accepted_publickey, :Accepted_password, 
      :Invalid_user, :Failed_password
    ]
    @high_events = [:Error, :Invalid_user, :Failed_password]
    @med_events  = [:Disconnect, :Accepted_publickey, :Accepted_password, :Session_opened, :Session_closed]
    @low_events  = [:Sudo_command]
    @login_events = [:Accepted_password, :Failed_password]
    @months = {"Jan" => "1", "Feb" => "2", "Mar" => "3", "Apr" => "4", "May" => "5", "Jun" => "6", "Jul" => "7", "Aug" => "8", "Sep" => "9", "Oct" => "10", "Nov" => "11", "Dec" => "12"}
    @hours = {"00" => 0, "01" => 0, "02" => 0, "03" => 0, "04" => 0, "05" => 0, "06" => 0, "07" => 0, "08" => 0, "09" => 0, "10" => 0, "11" => 0, "12" => 0, "13" => 0, "14" => 0, "15" => 0, "16" => 0, "17" => 0, "18" => 0, "19" => 0, "20" => 0, "21" => 0, "22" => 0, "23" => 0}
  end

  # Plots a bar graph for each event type with how many occurrences for each date in the dataset
  #
  # @param dataset - a hash containing {event_type => {date => count}, event_type => ...}
  def plot_day_series(dataset)
    result = {}
    dates = build_date_range # a hash containing a range of dates as keys with default values of 0

    @event_types.each do |symbol|
      result[symbol] = dates.clone 
      dataset[symbol].select { |event| event }.each do |event|
        date = event[:Date]
        result[symbol][date] += 1
      end
    end
  
    result.each do |event_type, date|
      x_values = result[event_type].keys
      y_values = result[event_type].values
      plot = UnicodePlot.barplot(x_values, y_values, title: "#{event_type} Event by Date").render  
    end
  end

  # Plots a bar graph for each event type with how many occurrences for each hour in the dataset
  # 
  # @param dataset - a hash containing {event_type => {hour => count}, event_type => ...}
  def plot_hour_series(dataset)
    puts dataset
    dataset.each do |event_type, hour|
      x_values = dataset[event_type].keys
      y_values = dataset[event_type].values
      plot = UnicodePlot.barplot(x_values, y_values, title: "#{event_type} Event by Hour").render
    end
  end

  # Sorts IPs in descending order and then plots a bar graph for the top 10 IPs found to be associated with high security events
  # 
  # @param dataset -  a hash containing IP as keys with hash values of events
  # {ip0 => {event0, event1, event2}, ip1 => {event0, event1, event2}...}
  def plot_ip_aggregate(dataset)
    sorted = dataset.sort_by { |ip, count| -count}
    s = sorted.to_h
    x = s.keys[0,10]
    y = s.values[0,10]
    plot = UnicodePlot.barplot(x, y, title: "Top 10 IPs by High Security Event").render
  end
  

  # Calls LogParser instance variable for a range of dates. The range of dates are then used to create a hash that can
  # be used for any date based analysis.
  # 
  # @returns result - a hash of date keys in ascending order with values of 0 
  # {"YYYY-MM-DD" => 0, "YYYY-MM-DD" => 0...}
  def build_date_range()
    result = {}
    range = []

    begin_date = Date.parse(@parser.date_range[0])
    end_date = Date.parse(@parser.date_range[1])
    begin_date.step(end_date) { |date| range << date.to_s }

    result = range.to_h { |key| [key, 0] }
    result
  end

  # Collects unique IP addresses and their associated high security events
  #       
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash containing IP as keys with hash values of events
  # {ip0 => {event0, event1, event2, ...}, ip1 => {event0, event1, event2, ...}...}
  def suspicious_ips(parsed_log)
    result = {}
    
    @high_events.each do |symbol|
      parsed_log[symbol].select { |event| event }.each do |event|    
        result[event[:Source_IP]] ||= 0 # Set result[ip] to new empty array if nil or doesn't exist
        result[event[:Source_IP]] += 1 # removed << event
      end 
    end
    plot_ip_aggregate(result)
    result
  end

  # Finds the number of occurrences of each type of event by the hour
  # 
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash of event type keys 
  # {event_type0 => {hour => count}, event_type1 => {hour => count}, ...}
  def events_by_hour(parsed_log)
    result = {}

    @event_types.each do |symbol|
      #result[symbol] = Marshal.load(Marshal.dump(@hours))
      result[symbol] = @hours.clone
      parsed_log[symbol].select { |event| event }.each do |event|
        time = event[:Time].split(":")
        hour = time[0] 
        result[symbol][hour] += 1
      end
    end
    plot_hour_series(result)
    result
  end

  # Finds the number of occurrences of each type of event by the day
  # 
  # @param parsed_log hash containing meta data for each event type 
  # @return result - a hash of event types with number of occurrences for each day that event took place
  # {event_type0 => {date => count, ...}, event_type1 => {date => count}, ...}
  def events_by_day(parsed_log)
    result = {}
    
    @event_types.each do |symbol|
      parsed_log[symbol].select { |event| event }.each do |event|
        date = event[:Date]
        result[symbol] ||= {}
        result[symbol][date] ||= 0
        result[symbol][date] += 1
      end
    end
    result
  end

  # Finds successful vs failed logins by the hour 
  #
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash of login events sorted by hour in the range of 00..23 with number of occurrences
  # {Accepted_password => {hour => count, ...} Failed_password => {hour ==> count}}
  def login_patterns(parsed_log)
    result = {}
    
    @login_events.each do |symbol|
      result[symbol] = @hours.clone
      parsed_log[symbol].select { |event| event }.each do |event|
        time = event[:Time].split(":")
        
        result[symbol][hour] += 1
      end
    end
    result
  end

  # Prints to console results sorted into severity type along with how many occurrences 
  # 
  # @param parsed_log hash containing meta data for each event type
  def get_summary(parsed_log)
    high_rows = []
    med_rows = []
    ops_rows = []
    
    high_rows << ["Error Flags", parsed_log[:Error].length]
    high_rows << ["Authentication failures", parsed_log[:Auth_failure].length]
    high_rows << ["Invalid users", parsed_log[:Invalid_user].length]
    high_rows << ["Failed password attempts", parsed_log[:Failed_password].length]

    med_rows << ["Disconnects", parsed_log[:Disconnect].length]
    med_rows << ["Accepted publickey", parsed_log[:Accepted_publickey].length]
    med_rows << ["Accepted password", parsed_log[:Accepted_password].length]
    med_rows << ["Session Opens", parsed_log[:Session_opened].length]
    med_rows << ["Session Closes", parsed_log[:Session_closed].length]

    ops_rows << ["Sudo usage", parsed_log[:Sudo_command].length]
    
    high_table = Terminal::Table.new :title => "High Security Concerns" , :headings => ['Event Type', 'Occurrences'], :rows => high_rows
    med_table = Terminal::Table.new :title => "Medium Security Concerns" , :headings => ['Event Type', 'Occurrences'], :rows => med_rows
    ops_table = Terminal::Table.new :title => "Operational Monitoring" , :headings => ['Event Type', 'Occurrences'], :rows => ops_rows

    puts high_table
    puts med_table 
    puts ops_table   
  end

end