## Security Log Analyzer

### Acknowledgements

* Thank you to the [Elastic team](https://github.com/elastic/examples/tree/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity) for providing the dataset used in this project.

  * Modifications: [test-auth.log](https://github.com/cskee004/log-analyzer/blob/main/data/auth-test.log)

[![Ruby Style Guide](https://img.shields.io/badge/code_style-rubocop-brightgreen.svg)](https://github.com/rubocop/rubocop)

[![Legacy Version](https://img.shields.io/badge/branch-development-purple)](https://github.com/cskee004/log-analyzer/tree/legacy-script-version)

---

### Requirements

* Ruby 3.1 or higher
* Rails 7.0 or higher

---

### Description

Log Analyzer is a Ruby on Rails application that parses and analyzes Linux system logs (auth.log). It extracts key security events, summarizes event patterns by date/hour, and visualizes the data through a dashboard interface.

This project is part of a personal portfolio and demonstrates experience with Ruby, Rails, log analysis, data visualization, and security-focused software design.

---

### Project Purpose

Security Log Analyzer began as a command-line log parser and evolved into a Rails-based interactive dashboard. The goal is to simplify security event tracking, highlight time-based patterns, and build a flexible tool that can evolve with new analysis features. It demonstrates practical Ruby/Rails skills, automated testing, and event-driven design for system security.

---

### Project Structure

```
├── app              # Rails MVC components
├── config           # Environment settings
├── db               # Database setup and schema
├── spec             # RSpec test files
├── data             # Test log files
```

---

### Features

* Upload and parse `auth.log` system logs
* Detect and classify key event types:
  * Error flags
  * Authentication failures
  * Invalid users
  * Failed password
  * Disconnects
  * Accepted publickey/passwords
  * Session open/closes
  * Sudo usage
* Event grouping by severity (high/medium/ops)
* Hourly and daily time-based summaries
* Top IPs triggering high-severity events
* Graphs powered by ApexCharts
* Modular design (LogParser, LogUtility, LogFileAnalyzer)
* RSpec test suite

---

### Dev Notes
- Parsing logic lives in `LogParser` and `LogUtility`
- Analysis is performed by `LogFileAnalyzer`
- Controller: `DashboardController`
- Partial views handle AJAX-based updates for summary and graphs

---

### Usage

#### Local Setup

```bash
git clone https://github.com/cskee004/log-analyzer.git
cd log-analyzer
bundle install
rails db:create db:migrate
rails server
```

Visit `http://localhost:3000` to use the web interface.

#### Uploading a Log File

1. Navigate to the dashboard homepage
2. Upload a Linux `auth.log` file using the form
3. View summary statistics and graphs from parsed results

---

### Testing

The project uses **RSpec** for testing models and controller logic.

#### Run Tests:

```bash
bundle exec rspec
```

Test coverage includes:

* Unit tests for parsing, utility, and analysis classes
* Controller specs for upload, summary, and graph actions

---

### Sample Output

---

### Roadmap

---

### Author

Chris Skeens
[LinkedIn](https://www.linkedin.com/in/christopher-skeens-846780248/)
