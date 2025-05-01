module DashboardHelper
  def light_contrasting_colors
    ["#2C3E50", "#8E44AD", "#E74C3C", "#16A085", "#2980B9", "#34495E", "#D35400", "#27AE60", "#F39C12", "#7F8C8D"]
  end

  def dark_contrasting_colors
    ["#ECF0F1", "#E67E22", "#F39C12", "#BDC3C7", "#F5B041", "#9B59B6", "#1ABC9C", "#DFF9FB", "#FF6347", "#FAD02E"]
  end
  
  def event_types
    %i[ error auth_failure disconnect session_opened session_closed sudo_command accepted_publickey
        accepted_password invalid_user failed_password]
  end

  def high_events
    %i[error invalid_user failed_password]
  end

  def med_events
    %i[disconnect accepted_publickey accepted_password session_opened session_closed]
  end

  def op_events
    %i[sudo_command]
  end

  def login_events
    %i[accepted_password failed_password]
  end
end
