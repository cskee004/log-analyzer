Rails.application.routes.draw do
  root "traces#index"
  get 'logs', to: 'dashboard#index', as: 'logs'
  post 'upload', to: 'dashboard#upload', as: 'upload'
  get 'dashboard/summary', to: 'dashboard#summary', as: 'summary_dashboard'
  get 'dashboard/graph', to: 'dashboard#graph', as: 'graph_dashboard'
  get '/reset', to: 'dashboard#reset', as: 'reset'
  get "up" => "rails/health#show", as: :rails_health_check
  resources :events
  resources :traces, only: [:index, :show] do
    collection { post :seed }
  end

  namespace :api do
    namespace :v1 do
      post "auth/token", to: "auth#token"
      post "telemetry",  to: "telemetry#create"
      post "keys",       to: "keys#create"
    end
  end
end
