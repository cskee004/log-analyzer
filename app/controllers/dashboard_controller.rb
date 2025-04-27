class DashboardController < ApplicationController
  def index
  end

  def upload
    
    @uploaded_file = params[:log_file]
    @log_utility = LogUtility.new
    results =  @log_utility.validate_file(@uploaded_file)
    if results.include?(false)
      puts results[1]
      # Render modal on upload tab with results[1]
    end
    
    @log_parser = LogParser.new
    @log = @log_parser.read_log(@uploaded_file)

    @log_file_analyzer = LogFileAnalyzer.new(@log_parser)
    @result_summary = @log_file_analyzer.get_summary(@log)
    
    
    @hour = @log_file_analyzer.events_by_hour(@log)
    @result_hour = @log_utility.format_for_apexcharts(@hour)

    @date = @log_file_analyzer.events_by_date(@log)
    @result_date = @log_utility.format_for_apexcharts(@date)

    @ip = @log_file_analyzer.top_offenders(@log)
    #@result_ip = @log_utility.format_for_apexcharts(@ip)
    puts @ip.inspect
   
    @login = @log_file_analyzer.login_patterns(@log)
    @result_login = @log_utility.format_for_apexcharts(@login)    

    render partial: 'summary', locals: { result_summary: @result_summary, result_hour: @result_hour, result_date: @result_date,  result_login: @result_login, ip: @ip }
    
  end

  def summary
    render partial: 'summary'
  end

  def graph
    render partial: 'graph'
  end

  def table
    render partial: 'table'
  end

end
