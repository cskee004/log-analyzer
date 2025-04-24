Rails.application.routes.draw do
  root "dashboard#index"
  post 'upload', to: 'dashboard#upload', as: 'upload'
  get 'dashboard/summary', to: 'dashboard#summary', as: 'dashboard_summary'
  get "up" => "rails/health#show", as: :rails_health_check

  resources :events
end
