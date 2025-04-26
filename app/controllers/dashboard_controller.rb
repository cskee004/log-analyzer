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

    @scaled_results = @results.map { | group | group.map { |event| { name: event[:name], data: event[:data] / 20.0}}}

    # @results[0] + results[1] + results[2] = all_events
    # @results[0] = high_events
    # @results[1] = med_events
    # @results[2] = ops_events

    render partial: 'summary', locals: { results: @results, scaled_results: @scaled_results}
    
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
