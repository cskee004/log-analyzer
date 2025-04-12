require "spec_helper"
require "preprocess_log"
require "analyze_log.rb"



describe "Analyze Log" do
  let(:log_parser) { LogParser.new }
  let(:log_analyzer) { LogAnalyzer.new(log_parser) }
  let(:log) { log_parser.read_log()}
  
  describe "suspicious_ips" do
    it "finds each high security event for each IP" do
      result = log_analyzer.suspicious_ips(log)
      expect(result["178.219.248.139"]).to eq(8)
    end
  end

  describe "events_by_hour" do
    it "counts how many times each event occurs by the hour" do
      result = log_analyzer.events_by_hour(log)
      expect(result[:Auth_failure]["10"]).to eq(10)
    end
  end

  describe "events_by_day" do
    it "counts how many times each event occurs by the day" do
      result = log_analyzer.events_by_day(log)
      expect(result[:Sudo_command]["2025-04-03"]).to eq(21)
    end
  end

  describe "login_patterns" do
    it "finds when accepted password and failed password events occur" do
      result = log_analyzer.login_patterns(log)
      expect(result[:Accepted_password]["20"]).to eq(7)
      expect(result[:Failed_password]["00"]).to eq(12)
    end
  end

  describe "plot_date_series" do 
    it "plots results from the analysis methods" do
      log_analyzer.plot_day_series(log)
      
    end
  end
end