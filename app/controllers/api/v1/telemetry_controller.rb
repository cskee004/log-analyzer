module Api
  module V1
    class TelemetryController < Api::V1::BaseController
      def create
        result = TelemetryIngester.call(request.raw_post)
        render json: result, status: :created
      rescue TelemetryIngester::Error => e
        render json: { error: e.message }, status: :unprocessable_content
      end
    end
  end
end
