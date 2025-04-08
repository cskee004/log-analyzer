require "spec_helper"
require "preprocess_log"
require "analyze_log.rb"



describe "Analyze Log" do
  let(:log_parser) { LogParser.new }
  let(:log_analyzer) { LogAnalyzer.new }
  let(:log) { log_parser.read_log()}
  
  describe "suspicious_ips" do
    it "returns hash of IPs that are tagged in the high security events category" do
      result = log_analyzer.suspicious_ips(log)
      expect(result["178.219.248.139"].length).to eq(8)
    end
  end

  describe "events_by_hour" do
    it "returns hash[event][hour] with the count for every hour" do
      result = log_analyzer.events_by_hour(log)
      expect(result[:Auth_failure][:"10"]).to eq(10)
    end
  end
end