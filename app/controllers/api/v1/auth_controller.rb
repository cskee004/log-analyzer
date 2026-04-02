module Api
  module V1
    class AuthController < ActionController::API
      def token
        api_key = ApiKey.authenticate(params[:token])

        if api_key
          render json: { valid: true, agent_type: api_key.agent_type }, status: :ok
        else
          render json: { error: "invalid or inactive token" }, status: :unauthorized
        end
      end
    end
  end
end
