class DashboardController < ApplicationController
  def index
  end

  def upload
    
    @uploaded_file = params[:log_file]
    @log_import = Utility.new
    results =  @log_import.validate_file(@uploaded_file)
    if results.include?(false)
      puts results[1]
    end
    
    #@log_parser = LogParser.new
    #@log = @log_parser.read_log(@uploaded_file)

    #@log_analyzer = LogFileAnalyzer.new(@log_parser)
    #@results = @log_analyzer.get_summary(@log)

    #@events = Event.all

    #render partial: 'summary', locals: { events: @events}
    
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
