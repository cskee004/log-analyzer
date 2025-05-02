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
    @log_utility.POST_events(parsed_log)
    
    log_file_analyzer = LogFileAnalyzer.new
    @result_summary = log_file_analyzer.get_summary(parsed_log)
    #@result_summary = @log_utility.rebuild_log('all')

    render partial: 'summary', locals: { result_summary: @result_summary }    
  end

  def summary
    @log_utility = LogUtility.new 
    @log_file_analyzer = LogFileAnalyzer.new
    
    all_events_log = @log_utility.rebuild_log('all')
    @result_summary = @log_file_analyzer.get_summary(all_events_log)

    render partial: 'summary', locals: { result_summary: @result_summary }
  end

  def graph
    @log_utility = LogUtility.new 
    @log_file_analyzer = LogFileAnalyzer.new
    
    dates = @log_utility.create_date_range
    all_events_log = @log_utility.rebuild_log('all')
    high_events_log = @log_utility.rebuild_log('high')
    med_events_log = @log_utility.rebuild_log('med')

    temp_top_ips = @log_file_analyzer.top_offenders(high_events_log)
    @top_ips = @log_utility.format_for_apexcharts(temp_top_ips)

    temp_high_date = @log_file_analyzer.events_by_date(high_events_log, dates)
    @high_date = @log_utility.format_for_apexcharts(temp_high_date)
    
    temp_high_hour = @log_file_analyzer.events_by_hour(high_events_log)
    @high_hour = @log_utility.format_for_apexcharts(temp_high_hour)

    temp_med_date = @log_file_analyzer.events_by_date(med_events_log, dates)
    @med_date = @log_utility.format_for_apexcharts(temp_med_date)
    
    temp_med_hour = @log_file_analyzer.events_by_hour(med_events_log)
    @med_hour = @log_utility.format_for_apexcharts(temp_med_hour)

    temp_login = @log_file_analyzer.login_patterns(all_events_log)
    @login = @log_utility.format_for_apexcharts(temp_login)
    

    render partial: 'graph', locals: {  top_ips: @top_ips, high_date: @high_date, high_hour: @high_hour,
                                        med_date: @med_date, med_hour: @med_hour, login: @login }
  end
  
  def table
    render partial: 'table'
  end

end
