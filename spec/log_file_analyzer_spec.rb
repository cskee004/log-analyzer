require 'spec_helper'
require_relative '../app/lib/log_parser'
require_relative '../app/lib/log_file_analyzer'

describe 'Analyze Log' do
  let(:log_parser) { LogParser.new }
  let(:log_file_analyzer) { LogFileAnalyzer.new }
  let(:log) { log_parser.read_log }

  describe 'top_offenders' do
    it 'returns the top 10 ips found to be associated with high security events' do
      result = log_file_analyzer.top_offenders(log)
      expect(result['201.178.81.113']).to eq(40)
    end
  end

  describe 'events_by_hour' do
    it 'returns how many times each event occurs by the hour' do
      result = log_file_analyzer.events_by_hour(log)
      expect(result[:authentication_failure]['10']).to eq(10)
    end
  end

  describe 'events_by_date' do
    it 'returns how many times each event occurs by the date' do
      date_range = { "2025-03-27" => 0, "2025-03-28" => 0, "2025-03-29" => 0, "2025-03-30" => 0,
                     "2025-03-31" => 0, "2025-04-01" => 0, "2025-04-02" => 0, "2025-04-03" => 0,
                     "2025-04-04" => 0, "2025-04-05" => 0, "2025-04-06" => 0, "2025-04-07" => 0,
                     "2025-04-08" => 0, "2025-04-09" => 0, "2025-04-10" => 0, "2025-04-11" => 0,
                     "2025-04-12" => 0, "2025-04-13" => 0, "2025-04-14" => 0, "2025-04-15" => 0,
                     "2025-04-16" => 0, "2025-04-17" => 0, "2025-04-18" => 0, "2025-04-19" => 0,
                     "2025-04-20" => 0 }
      result = log_file_analyzer.events_by_date(log, date_range)
      expect(result[:sudo_command]['2025-04-03']).to eq(21)
    end
  end

  describe 'login_patterns_hour' do
    it 'returns a hash containing accepted password and failed password events by the hour' do
      result = log_file_analyzer.login_patterns_hour(log)
      expect(result[:accepted_password]['20']).to eq(7)
      expect(result[:failed_password]['00']).to eq(12)
    end
  end

  describe 'login_patterns_date' do
    it 'returns a hash containing accepted password and failed password events by the hour' do
      date_range = { "2025-03-27" => 0, "2025-03-28" => 0, "2025-03-29" => 0, "2025-03-30" => 0,
                     "2025-03-31" => 0, "2025-04-01" => 0, "2025-04-02" => 0, "2025-04-03" => 0,
                     "2025-04-04" => 0, "2025-04-05" => 0, "2025-04-06" => 0, "2025-04-07" => 0,
                     "2025-04-08" => 0, "2025-04-09" => 0, "2025-04-10" => 0, "2025-04-11" => 0,
                     "2025-04-12" => 0, "2025-04-13" => 0, "2025-04-14" => 0, "2025-04-15" => 0,
                     "2025-04-16" => 0, "2025-04-17" => 0, "2025-04-18" => 0, "2025-04-19" => 0,
                     "2025-04-20" => 0 }
      result = log_file_analyzer.login_patterns_date(log, date_range)
      expect(result[:accepted_password]['2025-03-30']).to eq(75)
      expect(result[:failed_password]['2025-03-30']).to eq(173)
    end
  end

  describe 'get_summary' do
    it 'returns one entry per event type in EventTypes::ALL' do
      result = log_file_analyzer.get_summary({})
      expect(result.length).to eq(EventTypes::ALL.length)
    end

    it 'returns entries with labels matching EventTypes::LABELS in ALL order' do
      result = log_file_analyzer.get_summary({})
      expect(result.map { |r| r[:name] }).to eq(EventTypes::ALL.map { |t| EventTypes::LABELS[t] })
    end

    it 'counts zero for event types absent from parsed_log' do
      result = log_file_analyzer.get_summary({})
      expect(result.all? { |r| r[:data].values.first == 0 }).to be true
    end

    it 'returns the correct count for a present event type' do
      result = log_file_analyzer.get_summary({ sudo_command: ['a', 'b', 'c'] })
      sudo_entry = result.find { |r| r[:name] == 'Sudo usage' }
      expect(sudo_entry[:data]['Sudo usage']).to eq(3)
    end
  end
end
