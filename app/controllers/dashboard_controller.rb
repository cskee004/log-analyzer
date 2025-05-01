class DashboardController < ApplicationController
  def index
  end

  def upload
    
    @uploaded_file = params[:log_file]
    @log_utility = LogUtility.new
    @log_utility.DELETE_events
    results =  @log_utility.validate_file(@uploaded_file)
    if results.include?(false)
      puts results[1]
      # Render modal on upload tab with results[1]
    end
    
    
    log_parser = LogParser.new
    parsed_log = log_parser.read_log(@uploaded_file)
    puts parsed_log
    @log_utility.POST_events(parsed_log)
    
    log_file_analyzer = LogFileAnalyzer.new(log_parser)
    @result_summary = log_file_analyzer.get_summary(parsed_log)

    
    render partial: 'summary', locals: { result_summary: @result_summary }    
  end

  def summary
    render partial: 'summary'
  end

  def graph
    @log_utility = LogUtility.new 
    high = ['Error Flag', 'Authentication failure', 'Invalid user', 'Failed password']
    med = ['Disconnect', 'accepted_password', 'Accepted publickey', 'Session opened', 'Session closed']
    ops = ['Sudo command']
    
    dates = @log_utility.create_date_range()
    
    render partial: 'graph'
  end
  
  def table
    render partial: 'table'
  end

end
