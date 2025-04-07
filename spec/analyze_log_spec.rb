require "spec_helper"
require "preprocess_log"
require "analyze_log.rb"



describe "Analyze Log" do
  log_parser = LogParser.new
  log = log_parser.read_log()

  log_analyzer = LogAnalyzer.new

  describe "connects IP's to high security events" do
    it "returns suspicious IP's found in log" do
      result = log_analyzer.suspicious_ips(log)
      h = result["178.219.248.139"]
      expect(h.length).to eq(8)
    end
  end
end