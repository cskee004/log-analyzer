require_relative 'lib/analyze_log'
require_relative 'lib/preprocess_log'

def run_analyzer
  log_parser = LogParser.new
  log = log_parser.read_log('./data/auth.log')

  log_analyzer = LogAnalyzer.new(log_parser)
  log_analyzer.get_summary(log)
  log_analyzer.suspicious_ips(log)
  log_analyzer.events_by_hour(log)
  log_analyzer.events_by_date(log)

  puts 'Log analyzer complete'

end

run_analyzer if __FILE__ == $PROGRAM_NAME
