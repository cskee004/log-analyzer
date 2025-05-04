require 'rails_helper'

RSpec.describe DashboardController, type: :controller do
  let(:valid_file) { fixture_file_upload('./spec/fixtures/auth.log', 'application/octet-stream') }
  let(:parsed_log_mock) { [{ sample: 'event' }] }
  let(:summary_mock) { { events_count: 1 } }
  let(:empty_log) { {} }
  let(:apex_formatted_data) { [{ x: '01', y: 5 }] }

  before do
    allow_any_instance_of(LogUtility).to receive(:DELETE_events)
    allow_any_instance_of(LogUtility).to receive(:validate_file).and_return([true, 'All checks passed'])
    allow_any_instance_of(LogParser).to receive(:read_log).and_return(parsed_log_mock)
    allow_any_instance_of(LogUtility).to receive(:POST_events)
    allow_any_instance_of(LogFileAnalyzer).to receive(:get_summary).and_return(summary_mock)

    allow_any_instance_of(LogUtility).to receive(:create_date_range).and_return({})
    allow_any_instance_of(LogUtility).to receive(:rebuild_log).and_return(empty_log)
    allow_any_instance_of(LogFileAnalyzer).to receive(:top_offenders).and_return({})
    allow_any_instance_of(LogFileAnalyzer).to receive(:events_by_date).and_return({})
    allow_any_instance_of(LogFileAnalyzer).to receive(:events_by_hour).and_return({})
    allow_any_instance_of(LogFileAnalyzer).to receive(:login_patterns_date).and_return({})
    allow_any_instance_of(LogFileAnalyzer).to receive(:login_patterns_hour).and_return({})
    allow_any_instance_of(LogUtility).to receive(:format_for_apexcharts).and_return(apex_formatted_data)
  end

  describe 'index' do
    it 'renders the index template' do
      get :index
      expect(response).to be_successful
      expect(response).to render_template(:index)
    end
  end

  describe 'upload' do
    context 'with a valid log file' do
      it 'renders the summary partial' do
        post :upload, params: { log_file: valid_file }
        expect(response).to render_template(partial: '_summary')
      end
    end

    context 'with an invalid log file' do
      it 'renders the upload_error partial with message' do
        allow_any_instance_of(LogUtility).to receive(:validate_file).and_return([false, 'Invalid file'])
        post :upload, params: { log_file: valid_file }
        expect(response).to render_template(partial: '_upload_error')
      end
    end
  end

  describe 'summary' do
    it 'renders the summary partial' do
      get :summary
      expect(response).to render_template(partial: '_summary')
    end
  end

  describe 'graph' do
    it 'renders the graph partial with formatted data' do
      get :graph
      expect(response).to render_template(partial: '_graph')
    end
  end

  describe 'reset' do
    it 'deletes all events and redirects to root path with notice' do
      post :reset
      expect(response).to redirect_to(root_path)
      expect(flash[:notice]).to eq('Dashboard has been reset.')
    end
  end
end
