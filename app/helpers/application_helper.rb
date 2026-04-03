module ApplicationHelper
  # Formats a duration in seconds as "X.Xs", or "—" if nil (no spans recorded).
  def format_duration(seconds)
    return "—" if seconds.nil?

    "#{seconds.round(1)}s"
  end
end
