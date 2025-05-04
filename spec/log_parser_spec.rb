require 'spec_helper'
require_relative '../app/lib/log_parser'

describe 'Preprocess log' do
  log_parser = LogParser.new

  error = 'Mar 31 10:36:28 ip-10-77-20-248 sshd[19551]: error: maximum authentication attempts exceeded for root from
  122.191.89.89 port 37753 ssh2 [preauth]' # 3903
  describe 'parse_error' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for error event' do
      result = log_parser.parse_error(error, 3903, 'Error flag', 'Mar 31', '10:36:28', 'ip-10-77-20-248')
      expected =
        {
          line_number: 3903,
          event_type: 'Error flag',
          date: 'Mar 31',
          time: '10:36:28',
          host: 'ip-10-77-20-248',
          pid: '19551',
          message: 'error: maximum authentication attempts exceeded',
          user: 'root',
          source_ip: '122.191.89.89',
          source_port: '37753'
        }
      expect(result).to eq(expected)
    end
  end

  auth_fail = 'Mar 27 14:01:39 ip-10-77-20-248 sshd[2938]: Disconnecting: Too many authentication failures [preauth]'
  describe 'parse_auth_failure' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for a authentication failure event' do
      result = log_parser.parse_auth_failure(auth_fail, 87, 'Authentication failure', 'Mar 27', '14:01:39',
                                             'ip-10-77-20-248')
      expected =
        {
          line_number: 87,
          event_type: 'Authentication failure',
          date: 'Mar 27',
          time: '14:01:39',
          host: 'ip-10-77-20-248',
          pid: '2938',
          message: 'Disconnecting: Too many authentication failures'
        }
      expect(result).to eq(expected)
    end
  end

  disconnect = 'Mar 27 14:02:16 ip-10-77-20-248 sshd[2856]: Disconnected from 85.245.107.41 port 54866'
  describe 'parse_disconnected' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for a disconnected event' do
      log_parser = LogParser.new
      result = log_parser.parse_disconnect(disconnect, 89, 'Disconnect', 'Mar 27', '14:02:16', 'ip-10-77-20-248')
      expected =
        {
          line_number: 89,
          event_type: 'Disconnect',
          date: 'Mar 27',
          time: '14:02:16',
          host: 'ip-10-77-20-248',
          pid: '2856',
          source_ip: '85.245.107.41',
          source_port: '54866'
        }
      expect(result).to eq(expected)
    end
  end

  open = 'Mar 27 13:09:37 ip-10-77-20-248 sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)'
  describe 'parse_session_open' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for a session open event' do
      result = log_parser.parse_session_open(open, 11, 'Session opened', 'Mar 27', '13:09:37', 'ip-10-77-20-248')
      expected =
        {
          line_number: 11,
          event_type: 'Session opened',
          date: 'Mar 27',
          time: '13:09:37',
          host: 'ip-10-77-20-248',
          user: 'root'
        }
      expect(result).to eq(expected)
    end
  end

  close = 'Mar 27 13:09:38 ip-10-77-20-248 sudo: pam_unix(sudo:session): session closed for user root'
  describe 'parse_session_close' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for a session closed event' do
      result = log_parser.parse_session_close(close, 12, 'Session closed', 'Mar 27', '13:09:38', 'ip-10-77-20-248')
      expected =
        {
          line_number: 12,
          event_type: 'Session closed',
          date: 'Mar 27',
          time: '13:09:38',
          host: 'ip-10-77-20-248',
          user: 'root'
        }
      expect(result).to eq(expected)
    end
  end

  sudo = 'Mar 27 13:11:35 ip-10-77-20-248 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ;
  COMMAND=/usr/bin/apt-get install packetbeat' # 37
  describe 'parse_sudo_command' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for a sudo command event' do
      result = log_parser.parse_sudo_command(sudo, 37, 'Sudo command', 'Mar 27', '13:11:35', 'ip-10-77-20-248')
      expected =
        {
          line_number: 37,
          event_type: 'Sudo command',
          date: 'Mar 27',
          time: '13:11:35',
          host: 'ip-10-77-20-248',
          directory: '/home/ubuntu',
          user: 'root',
          command: '/usr/bin/apt-get install packetbeat'
        }
      expect(result).to eq(expected)
    end
  end

  accepted = 'Mar 28 14:09:55 ip-10-77-20-248 sshd[29069]: Accepted publickey for ubuntu from 85.245.107.41 port 55779
  ssh2: RSA SHA256:Kl8kPGZrTiz7g4FO1hyqHdsSBBb5Fge6NWOobN03XJg' # 841
  describe 'parse_accept_event' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for an accept event' do
      result = log_parser.parse_accept_event(accepted, 841, 'Accept event', 'Mar 28', '14:09:55', 'ip-10-77-20-248')
      expected =
        {
          line_number: 841,
          event_type: 'Accept event',
          date: 'Mar 28',
          time: '14:09:55',
          host: 'ip-10-77-20-248',
          pid: '29069',
          message: 'Accepted publickey',
          user: 'ubuntu',
          source_ip: '85.245.107.41',
          source_port: '55779',
          key: 'Kl8kPGZrTiz7g4FO1hyqHdsSBBb5Fge6NWOobN03XJg'
        }
      expect(result).to eq(expected)
    end
  end

  invalid_user = 'Mar 31 06:34:36 ip-10-77-20-248 sshd[18539]: Invalid user pruebas from 60.187.118.40' # 3741
  describe 'parse_invalid_user' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for an invalid user event' do
      result = log_parser.parse_invalid_user(invalid_user, 3741, 'Invalid user', 'Mar 31', '06:34:36',
                                             'ip-10-77-20-248')
      expected =
        {
          line_number: 3741,
          event_type: 'Invalid user',
          date: 'Mar 31',
          time: '06:34:36',
          host: 'ip-10-77-20-248',
          pid: '18539',
          user: 'pruebas',
          source_ip: '60.187.118.40'
        }
      expect(result).to eq(expected)
    end
  end

  failed_password = 'Mar 31 06:34:38 ip-10-77-20-248 sshd[18539]: Failed password for invalid user pruebas from
  60.187.118.40 port 41838 ssh2' # 3745
  describe 'parse_failed_password' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for a failed password event' do
      result = log_parser.parse_failed_password(failed_password, 3745, 'Failed password', 'Mar 31', '06:34:38',
                                                'ip-10-77-20-248')
      expected =
        {
          line_number: 3745,
          event_type: 'Failed password',
          date: 'Mar 31',
          time: '06:34:38',
          host: 'ip-10-77-20-248',
          pid: '18539',
          user: 'pruebas',
          source_ip: '60.187.118.40',
          source_port: '41838'
        }
      expect(result).to eq(expected)
    end
  end

  describe 'read_log' do
    let(:log_parser) { LogParser.new }
    it 'parses log into a structured format' do
      log = log_parser.read_log('./data/auth.log')
      expect(log[:error_flag].length).to eq(189)
      expect(log[:authentication_failure].length).to eq(673)
      expect(log[:disconnect].length).to eq(307)
      expect(log[:session_opened].length).to eq(1268)
      expect(log[:session_closed].length).to eq(1074)
      expect(log[:sudo_command].length).to eq(186)
      expect(log[:accepted_publickey].length).to eq(36)
      expect(log[:accepted_password].length).to eq(190)
      expect(log[:invalid_user].length).to eq(177)
      expect(log[:failed_password].length).to eq(713)
    end
  end

  describe 'sanitize_date' do
    let(:log_parser) { LogParser.new }
    it 'converts a string date into a date object' do
      result = log_parser.sanitize_date('Apr 14')
      expect(result).to eq('2025-04-14')
    end
  end

  describe 'get_date_range' do
    let(:log_parser) { LogParser.new }
    it 'returns a range of dates from first to last date from log' do
      result = log_parser.get_date_range
      expected = {  '2025-03-27' => 0, '2025-03-28' => 0, '2025-03-29' => 0, '2025-03-30' => 0, '2025-03-31' => 0,
                    '2025-04-01' => 0, '2025-04-02' => 0, '2025-04-03' => 0, '2025-04-04' => 0, '2025-04-05' => 0,
                    '2025-04-06' => 0, '2025-04-07' => 0, '2025-04-08' => 0, '2025-04-09' => 0, '2025-04-10' => 0,
                    '2025-04-11' => 0, '2025-04-12' => 0, '2025-04-13' => 0, '2025-04-14' => 0, '2025-04-15' => 0,
                    '2025-04-16' => 0, '2025-04-17' => 0, '2025-04-18' => 0, '2025-04-19' => 0, '2025-04-20' => 0 }
      expect(result).to eq(expected)
    end
  end
end
