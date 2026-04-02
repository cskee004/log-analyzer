module Api
  module V1
    class BaseController < ActionController::API
      before_action :authenticate_api_key!

      private

      def authenticate_api_key!
        token = bearer_token
        @current_api_key = ApiKey.authenticate(token) if token

        render json: { error: "unauthorized" }, status: :unauthorized unless @current_api_key
      end

      def bearer_token
        header = request.headers["Authorization"]
        header&.delete_prefix("Bearer ")&.strip.presence
      end
    end
  end
end
