require 'spec_helper'
require 'preprocess_log'

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
          Line_number: 3903,
          Type: 'Error flag',
          Date: 'Mar 31',
          Time: '10:36:28',
          Host: 'ip-10-77-20-248',
          PID: '19551',
          Message: 'error: maximum authentication attempts exceeded',
          User: 'root',
          Source_IP: '122.191.89.89',
          Source_port: '37753'
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
          Line_number: 87,
          Type: 'Authentication failure',
          Date: 'Mar 27',
          Time: '14:01:39',
          Host: 'ip-10-77-20-248',
          PID: '2938',
          Message: 'Disconnecting: Too many authentication failures'
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
          Line_number: 89,
          Type: 'Disconnect',
          Date: 'Mar 27',
          Time: '14:02:16',
          Host: 'ip-10-77-20-248',
          PID: '2856',
          Source_IP: '85.245.107.41',
          Source_port: '54866'
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
          Line_number: 11,
          Type: 'Session opened',
          Date: 'Mar 27',
          Time: '13:09:37',
          Host: 'ip-10-77-20-248',
          User: 'root'
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
          Line_number: 12,
          Type: 'Session closed',
          Date: 'Mar 27',
          Time: '13:09:38',
          Host: 'ip-10-77-20-248',
          User: 'root'
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
          Line_number: 37,
          Type: 'Sudo command',
          Date: 'Mar 27',
          Time: '13:11:35',
          Host: 'ip-10-77-20-248',
          Directory: '/home/ubuntu',
          User: 'root',
          Command: '/usr/bin/apt-get install packetbeat'
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
          Line_number: 841,
          Type: 'Accept event',
          Date: 'Mar 28',
          Time: '14:09:55',
          Host: 'ip-10-77-20-248',
          PID: '29069',
          Message: 'Accepted publickey',
          User: 'ubuntu',
          Source_IP: '85.245.107.41',
          Source_port: '55779',
          Key: 'Kl8kPGZrTiz7g4FO1hyqHdsSBBb5Fge6NWOobN03XJg'
        }
      expect(result).to eq(expected)
    end
  end

  invalid_user = 'Mar 31 06:34:36 ip-10-77-20-248 sshd[18539]: Invalid user pruebas from 60.187.118.40' # 3741
  describe 'parse_invalid_user' do
    let(:log_parser) { LogParser.new }
    it 'returns a hash of meta data for an invalid user event' do
      result = log_parser.parse_invalid_user( invalid_user, 3741, 'Invalid user', 'Mar 31', '06:34:36',
                                              'ip-10-77-20-248')
      expected =
        {
          Line_number: 3741,
          Type: 'Invalid user',
          Date: 'Mar 31',
          Time: '06:34:36',
          Host: 'ip-10-77-20-248',
          PID: '18539',
          User: 'pruebas',
          Source_IP: '60.187.118.40'
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
          Line_number: 3745,
          Type: 'Failed password',
          Date: 'Mar 31',
          Time: '06:34:38',
          Host: 'ip-10-77-20-248',
          PID: '18539',
          User: 'pruebas',
          Source_IP: '60.187.118.40',
          Source_port: '41838'
        }
      expect(result).to eq(expected)
    end
  end

  describe 'read_log' do
    let(:log_parser) { LogParser.new }
    it 'parses log into a structured format' do
      log = log_parser.read_log('./data/auth.log')
      expect(log[:Error].length).to eq(189)
      expect(log[:Auth_failure].length).to eq(673)
      expect(log[:Disconnect].length).to eq(307)
      expect(log[:Session_opened].length).to eq(1268)
      expect(log[:Session_closed].length).to eq(1074)
      expect(log[:Sudo_command].length).to eq(186)
      expect(log[:Accepted_publickey].length).to eq(36)
      expect(log[:Accepted_password].length).to eq(190)
      expect(log[:Invalid_user].length).to eq(177)
      expect(log[:Failed_password].length).to eq(713)
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
