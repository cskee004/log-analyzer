## Security Log Analyzer

### Acknowledgements

- Thank you to the [Elastic team](https://github.com/elastic/examples/tree/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity) for providing the dataset used in this project.

    - Modifications: [test-auth.log](https://github.com/cskee004/log-analyzer/blob/main/data/auth-test.log)

- This project also uses [unicode_plot.rb](https://github.com/red-data-tools/unicode_plot.rb) by Kenta Murata, licensed under the MIT License.

### Description

Log Analyzer is a Ruby-based tool thats designed to parse and analyze Linux system logs. It extracts key events, tracks time trends, and prepares that data for further visualization or reporting. 

### Project Purpose

This project is both a personal learning tool and a practical log analysis pipeline. The goal is to simplify the process of examining Linux 'auth.log' files, highlight time based patterns, and generate structured data for further use. 

### Project Structure
```
|── data/            # Sample log files
├── docs/            # Generated datasets, graphs, and testing reports
├── lib/             # Parsing and analyze classes
├── main.rb/         # Program main driver
├── README.md/       # Project overview
└── spec/            # RSpec unit tests
```

### Features
- Parse `auth.log` system logs for eight different event types
- Basic event counting and grouping
- Hourly and daily breakdown of events
- Top 10 IP's connected to security events
- Tested with RSpec for reliability

### Usage
- Clone the repo
```
git clone https://github.com/cskee004/log-analyzer.git
cd log-analyzer
```
- Install dependencies
```
bundle install
```
- Run the analyzer
```
ruby main.rb
```
- Find results
```
results/datasets/
results/graphs/
```

### Testing
- Run the RSpec test suite
```
bundle exec rspec
```
- Test results
```
results/tests/
```

### Sample Ouput


[![Ruby Style Guide](https://img.shields.io/badge/code_style-rubocop-brightgreen.svg)](https://github.com/rubocop/rubocop)
