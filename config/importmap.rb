# Pin npm packages by running ./bin/importmap

pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"
pin "@hotwired/stimulus-loading", to: "stimulus-loading.js"
pin "modern-normalize", to: "https://cdn.jsdelivr.net/npm/modern-normalize@latest/modern-normalize.css"
pin "apexcharts", to: "https://cdnjs.cloudflare.com/ajax/libs/apexcharts/4.5.0/apexcharts.min.css"
pin_all_from "app/javascript/controllers", under: "controllers"
