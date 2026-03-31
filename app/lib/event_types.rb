# EventTypes module
# Canonical symbol-based constants for all event type groupings used across the log analyzer.
#
# HIGH vs HIGH_SECURITY differ intentionally:
#   HIGH         — events used for IP offense ranking (LogFileAnalyzer#top_offenders)
#   HIGH_SECURITY — events used for DB/UI security-level filtering (LogUtility#rebuild_log)
module EventTypes
  ALL           = %i[error_flag authentication_failure disconnect session_opened session_closed
                     sudo_command accepted_publickey accepted_password invalid_user failed_password].freeze
  HIGH          = %i[error_flag invalid_user failed_password].freeze
  HIGH_SECURITY = %i[error_flag authentication_failure invalid_user failed_password].freeze
  MEDIUM        = %i[disconnect accepted_publickey accepted_password session_opened session_closed].freeze
  OPS           = %i[sudo_command].freeze
  LOGIN         = %i[accepted_password failed_password].freeze
end
