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
    @results = @log_file_analyzer.get_summary(@log)

    #render partial: 'summary', locals: { results: @results}
    
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
