class TracesController < ApplicationController
  def index
    @traces = Trace.includes(:spans).order(start_time: :desc)
  end

  def show
    @trace = Trace.find_by!(trace_id: params[:id])
    @spans = @trace.spans.order(:timestamp)
    @span_latencies = compute_latencies(@spans)
    @total_duration = total_duration(@spans)
  end

  def seed
    result = SimulatorSeeder.call
    if result.errors.empty?
      redirect_to traces_path, notice: "Generated #{result.traces_created} traces."
    else
      redirect_to traces_path, alert: "Generated #{result.traces_created} traces (#{result.errors.size} failed)."
    end
  end

  private

  def compute_latencies(spans)
    latencies = {}
    spans.each_cons(2) do |current, nxt|
      latencies[current.span_id] = nxt.timestamp - current.timestamp
    end
    latencies
  end

  def total_duration(spans)
    return nil if spans.size < 2

    spans.last.timestamp - spans.first.timestamp
  end
end
