module Api
  module V1
    class KeysController < ActionController::API
      def create
        api_key = ApiKey.create!(agent_type: params[:agent_type])
        render json: {
          token:      api_key.token,
          agent_type: api_key.agent_type,
          message:    "Store this token securely — it will not be shown again."
        }, status: :created
      rescue ActiveRecord::RecordInvalid => e
        render json: { error: e.message }, status: :unprocessable_content
      end
    end
  end
end
