require 'spec_helper'
require 'rails_helper'
require 'rack/test'
require_relative '../app/lib/log_parser'
require_relative '../app/lib/log_file_analyzer'
require_relative '../app/lib/log_utility'

include Rack::Test::Methods

describe 'Log utility' do
  let(:log_parser) { LogParser.new }
  let(:log_file_analyzer) { LogFileAnalyzer.new }
  let(:log_utility) { LogUtility.new }
  let(:log) { log_parser.read_log }


  describe 'POST_events' do
    it 'inserts the parsed results into the Event model' do
      log_utility.POST_events(log)
      size = Event.count
      expect(Event.last[:id]).to eq(size)
      log_utility.DELETE_events
    end
  end

  describe 'DELETE_events' do
    it 'clears out contents of the Event model' do
      log_utility.POST_events(log)
      size = Event.count
      expect(Event.last[:id]).to eq(size)
      log_utility.DELETE_events
      expect(Event.count).to eq(0)
    end
  end

  describe 'validate_file' do
    it 'returns an array containing the bool and message from the validator' do
      file_content = Rack::Test::UploadedFile.new(Rails.root.join('spec/fixtures/wrong-type.txt'), 'text/plain')
      file_big = Rack::Test::UploadedFile.new(Rails.root.join('spec/fixtures/auth-test-size.log'), 'application/octet-stream')
      file_empty = Rack::Test::UploadedFile.new(Rails.root.join('spec/fixtures/auth-test-empty.log'),'application/octet-stream')
      file = Rack::Test::UploadedFile.new(Rails.root.join('spec/fixtures/auth.log'), 'application/octet-stream')
      result = log_utility.validate_file(file_content)
      expect(result).to eq([false, "Content type failed: #{file_content.content_type}"])
      result = log_utility.validate_file(file_big)
      expect(result).to eq([false, "File size too big: #{file_big.size} bytes"])
      result = log_utility.validate_file(file_empty)
      expect(result).to eq([false, "File empty: #{file_empty.size} bytes"])
      result = log_utility.validate_file(file)
      expect(result).to eq([true, "All checks passed"])
    end
  end
  
  describe 'format_for_apexcharts' do
    it 'returns the given hash as an array of name-data hashes' do
      input = {accepted_password: {"00" => 5, "01" => 2}, failed_password: {"00" => 3, "01" => 4}}
      expected_output = [ {name: 'accepted_password', data: {"00" => 5, "01" => 2}},
                          {name: 'failed_password',   data: {"00" => 3, "01" => 4}} ]
      result = log_utility.format_for_apexcharts(input)
      expect(result).to eq(expected_output)
  end
end

  describe 'create_date_range' do
    it 'returns a hash of dates from Event.first to Event.last all initialized to 0' do
      log_utility.POST_events(log)
      expected_output = { "2025-03-27"=>0, "2025-03-28"=>0, "2025-03-29"=>0, "2025-03-30"=>0, "2025-03-31"=>0, 
                          "2025-04-01"=>0, "2025-04-02"=>0, "2025-04-03"=>0, "2025-04-04"=>0, "2025-04-05"=>0, 
                          "2025-04-06"=>0, "2025-04-07"=>0, "2025-04-08"=>0, "2025-04-09"=>0, "2025-04-10"=>0, 
                          "2025-04-11"=>0, "2025-04-12"=>0, "2025-04-13"=>0, "2025-04-14"=>0, "2025-04-15"=>0, 
                          "2025-04-16"=>0, "2025-04-17"=>0, "2025-04-18"=>0, "2025-04-19"=>0, "2025-04-20"=>0 }
      result = log_utility.create_date_range
      expect(result).to eq(expected_output)
    end
  end

  describe 'rebuild_log' do
    it 'returns a hash of event_type symbols mapped to event data hashes for the given security level' do
    Event.create!(
      line_number: 1, event_type: 'Error flag', date: '2024-05-01', time: '10:00:00',
      host: 'host1', pid: '1111', message: 'System error detected', user: 'root',
      source_ip: '10.0.0.1', source_port: '2222', directory: nil, command: nil, key: nil
    )
    Event.create!(
      line_number: 2, event_type: 'Authentication failure', date: '2024-05-01', time: '10:05:00',
      host: 'host2', pid: '2222', message: 'Failed password for invalid user', user: 'unknown',
      source_ip: '10.0.0.2', source_port: '2222', directory: nil, command: nil, key: nil
    )
    Event.create!(
      line_number: 3, event_type: 'Invalid user', date: '2024-05-01', time: '10:10:00',
      host: 'host3', pid: '3333', message: 'Invalid user admin from 10.0.0.3', user: 'admin',
      source_ip: '10.0.0.3', source_port: '2222', directory: nil, command: nil, key: nil
    )
    Event.create!(
      line_number: 4, event_type: 'Failed password', date: '2024-05-01', time: '10:15:00',
      host: 'host4', pid: '4444', message: 'Failed password for user test', user: 'test',
      source_ip: '10.0.0.4', source_port: '2222', directory: nil, command: nil, key: nil
    )
    result = log_utility.rebuild_log('high')
    expect(result.keys).to contain_exactly(:error_flag, :authentication_failure, :invalid_user, :failed_password)
    expect(result[:error_flag].first[:message]).to include('System error')
    expect(result[:authentication_failure].first[:user]).to eq('unknown')
    expect(result[:invalid_user].first[:source_ip]).to eq('10.0.0.3')
    expect(result[:failed_password].first[:host]).to eq('host4')
  end
end


end