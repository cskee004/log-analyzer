require 'terminal-table'
require 'fileutils'
require 'unicode_plot'
require 'json'

# LogAnalyzer Class
# This class is responsible for analyzing security related events found in parsed_log. This class makes the
#   following assumptions...
# High Security Concerns:
# - Error Flags: Repeated errors could indicate malicious network patterns, suspicious login hours, or abnormal
#   sequences of actions
# - Authentication failures: Many failures in a short time could indicate brute-force or credential stuffing attacks
# - Invalid user: Usernames that don't exist could indicate brute-force attempts
# - Failed password: The wrong password could be a legitimate error by the user or brute-force attempts
# Medium Security Concerns:
# - Disconnects: Abnormal disconnects could indicate session hijacking or instability due to network load
# - Accepted publickey and passwords: Logins from strange IPs using a password
# - Session opens/closes: Unusual session durations, late-night activity, or sessions without proper closure
# could indicate system compromise
# Operation Monitoring:
# - Sudo commands: Sudo usage from non-admins could indicate insider threats or privilege abuse
#
# Usage:
#   log_analyzer = LogAnalyzer.new(log_parser)
#   log_analyzer.get_summary(log)
#
# Attributes:
# - 'parser' LogParser : instance variable
# - 'event_types' array : collection of event type symbols to control loops
# - 'high_events'array : collection of high security event symbols
# - 'med_events' array : medium security symbols
# - 'low_events' array : low security symbols
# - 'login_events' array : more symbols
# - 'months' hash : helper for converting 3 letter month abbreviations to the months numerical representation
# - 'hours' hash : helper for normalizing datasets that use hour based analysis
#
# Methods:
# - 'plot_time_series' : Creates a bar graph where x-values represent the time unit(hour or date) and y-values represent
#   event counts in the time unit
# - 'plot_ip_aggregate' : Creates a bar graph where x-values represent flagged ip addresses and y-values represent high
#   security event counts
# - 'top_offenders' : Rank top 10 IPs by number of high security concerns
# - 'events_by_hour' : Finds what event type happens during each hour of the day
# - 'events_by_date' : Finds what event type happens during each hour or date
# - 'login_patterns' : Reports when users typically log in and when failures occur
# - 'save_json' : Helper function to save the given dataset in json format
# - 'save_graph' : Helper function to save the given plot object
# - 'get_summary' : prints tables to the console that summarize the results from LogParser

class LogFileAnalyzer
  def initialize()
    @event_types = %i[error_flag authentication_failure disconnect session_opened session_closed sudo_command accepted_publickey
                      accepted_password invalid_user failed_password]
    @high_events = %i[error_flag invalid_user failed_password]
    @med_events  = %i[disconnect accepted_publickey accepted_password session_opened session_closed]
    @low_events  = %i[sudo_command]
    @login_events = %i[accepted_password failed_password]
    @months = { 'Jan' => '1', 'Feb' => '2', 'Mar' => '3', 'Apr' => '4', 'May' => '5', 'Jun' => '6', 'Jul' => '7',
                'Aug' => '8', 'Sep' => '9', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12' }
    @hours = {  '00' => 0, '01' => 0, '02' => 0, '03' => 0, '04' => 0, '05' => 0, '06' => 0, '07' => 0, '08' => 0,
                '09' => 0, '10' => 0, '11' => 0, '12' => 0, '13' => 0, '14' => 0, '15' => 0, '16' => 0, '17' => 0,
                '18' => 0, '19' => 0, '20' => 0, '21' => 0, '22' => 0, '23' => 0 }
  end

  # Plots a bar graph for each event type with how many occurrences for each day or date in the dataset
  #
  # @param dataset - a hash containing {event_type => {date || hour => count}, event_type => ...}

  def plot_time_series(dataset, time_unit)
    dataset.each_key do |event_type|
      save_json(dataset, time_unit)
      x_values = dataset[event_type].keys
      y_values = dataset[event_type].values
      case time_unit
      when /date/
        plot = UnicodePlot.barplot(x_values, y_values, title: "#{event_type} Event by Date")
        save_graph(plot, event_type, time_unit)
      when /hour/
        plot = UnicodePlot.barplot(x_values, y_values, title: "#{event_type} Event by Hour")
        save_graph(plot, event_type, time_unit)
      end
    end
  end

  # Sorts IP addresses in descending order and then plots a bar graph for the top 10 IPs found to be associated with high
  # security events
  #
  # @param dataset -  a hash containing IP as keys with hash values of events
  #                  {ip0 => {event0, event1, event2}, ip1 => {event0, event1, event2}...}

  def plot_ip_aggregate(dataset)
    sorted = dataset.sort_by { |_ip, count| -count }
    s = sorted.to_h
    x = s.keys[0, 10]
    y = s.values[0, 10]
    plot = UnicodePlot.barplot(x, y, title: 'Top 10 IPs by High Security Event')
    output = StringIO.new
    plot.render(output)

    path = 'docs/results/graphs/sus_IPs.txt'
    dir = File.dirname(path)
    FileUtils.mkdir_p(dir) unless File.exist?(dir)

    File.delete(path) if File.exist?(path)
    File.open(path, 'w') { |file| file.write(plot.to_s) }
  end

  # Collects unique IP addresses and their associated high security events. Results are then sorted 
  # by number of high security events associated with the IP
  #
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash containing IP as keys and counts for each associated high security event
  #                 {ip0 => n, ip1 => n, ...}

  def top_offenders(parsed_log)
    result = {}
    @high_events.each do |symbol|
      next unless parsed_log[symbol]
      parsed_log[symbol].select { |event| event }.each do |event|
        result[event[:source_ip]] ||= 0
        result[event[:source_ip]] += 1
      end
    end
    sorted = result.sort_by { |_ip, count| -count }
    final_sorted = sorted.to_a.first(10).to_h
    final_sorted
  end

  # Finds the number of occurrences of each type of event by the hour
  #
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash of event type keys
  #                 {event_type0 => {hour => count}, event_type1 => {hour => count}, ...}

  def events_by_hour(parsed_log)
    result = {}

    @event_types.each do |symbol|
      next unless parsed_log[symbol] 
      result[symbol] = @hours.clone
      parsed_log[symbol].select { |event| event }.each do |event|
        time = event[:time].split(':')
        hour = time[0]
        result[symbol][hour] += 1
      end
    end
    result
  end

  # Finds the number of occurrences of each type of event by the day
  #
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash of event types with number of occurrences for each day that event took place
  #                 {event_type0 => {date => count, ...}, event_type1 => {date => count}, ...}

  def events_by_date(parsed_log, date_range)
    result = {}
    @event_types.each do |symbol|
      next unless parsed_log[symbol]
      result[symbol] = date_range
      parsed_log[symbol].select { |event| event }.each do |event|
        date = event[:date]
        result[symbol][date] += 1
      end
    end
    result
  end

  # Finds successful vs failed logins by the hour
  #
  # @param parsed_log hash containing meta data for each event type
  # @return result - a hash of login events sorted by hour in the range of 00..23 with number of occurrences
  #                 {Accepted_password => {hour => count, ...} Failed_password => {hour ==> count}}
  
  def login_patterns(parsed_log)
    result = {}
    @login_events.each do |symbol|
      next unless parsed_log[symbol]
      result[symbol] = @hours.clone
      parsed_log[symbol].select { |event| event }.each do |event|
        time = event[:time].split(':')
        hour = time[0]
        result[symbol][hour] += 1
      end
    end
    result
  end

  # Helper function to convert the given hash into JSON
  #
  # @param dataset - a hash containing structured meta data 
  # @param time_unit - hour or date
  
  def save_json(dataset, time_unit)
    dataset.each_key do |event_type|
      x_values = dataset[event_type].keys
      y_values = dataset[event_type].values

      data = { time_unit.to_s => x_values, 'values' => y_values }
      path = "docs/results/datasets/#{event_type}_#{time_unit}.json"
      dir = File.dirname(path)
      FileUtils.mkdir_p(dir) unless File.exist?(dir)

      File.delete(path) if File.exist?(path)
      File.open(path, 'w') { |file| file.write(data.to_json) }
    end
  end

  # Helper function to save graphing result to a text document
  # 
  # @plot - graph
  # @event_type - the security event
  # @time_unit - hour or date

  def save_graph(plot, event_type, time_unit)
    output = StringIO.new
    plot.render(output)

    path = "docs/results/graphs/#{event_type}_#{time_unit}.txt"
    dir = File.dirname(path)
    FileUtils.mkdir_p(dir) unless File.exist?(dir)

    File.delete(path) if File.exist?(path)
    File.open(path, 'w') { |file| file.write(plot.to_s) }
  end

  # Counts each event type number of occurrences found in the parsed_log
  #
  # @param parsed_log hash containing meta data for each event type
  # @return results - an array of hashes containing event types with corresponding totals found in parsed_log
  #                   results[{name: event, data: {event => count}], ...]
  #                            
  def get_summary(parsed_log)
    results = []

    results << {name: 'Error Flags', data: {'Error Flags' => parsed_log.fetch(:error_flag, []).length}}
    results << {name: 'Authentication failures', data: {'Authentication failures' => parsed_log.fetch(:authentication_failure, []).length}}
    results << {name: 'Invalid users', data: {'Invalid users' => parsed_log.fetch(:invalid_user, []).length}}
    results << {name: 'Failed password attempts', data: {'Failed password attempts' => parsed_log.fetch(:failed_password, []).length}}
    results << {name: 'Disconnects', data: {'Disconnects' => parsed_log.fetch(:disconnect, []).length}}
    results << {name: 'Accepted publickey', data: {'Accepted Publickey' => parsed_log.fetch(:accepted_publickey, []).length}}
    results << {name: 'Accepted password', data: {'Accepted password' => parsed_log.fetch(:accepted_password, []).length}}
    results << {name: 'Session Opens', data: {'Session Opens' => parsed_log.fetch(:session_opened, []).length}}
    results << {name: 'Session Closes', data: {'Session Closes' => parsed_log.fetch(:session_closed, []).length}}
    results << {name: 'Sudo usage', data: {'Sudo Usage' => parsed_log.fetch(:sudo_command, []).length}}
  
    results
  end
end
