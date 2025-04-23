## Security Log Analyzer  

***

### Branches

[![Main](https://img.shields.io/badge/branch-main-brightgreen)](https://github.com/cskee004/log-analyzer/tree/main) 

[![Development](https://img.shields.io/badge/branch-development-yellow)](https://github.com/cskee004/log-analyzer/tree/development) - Active feature development (latest work)

***

### Acknowledgements

- Thank you to the [Elastic team](https://github.com/elastic/examples/tree/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity) for providing the dataset used in this project.

    - Modifications: [test-auth.log](https://github.com/cskee004/log-analyzer/blob/main/data/auth-test.log)

- This project also uses [unicode_plot.rb](https://github.com/red-data-tools/unicode_plot.rb) by Kenta Murata, licensed under the MIT License.

***

### Description

Log Analyzer is a Ruby-based tool thats designed to parse and analyze Linux system logs. It extracts key events, tracks time trends, and prepares the data for further visualizations or reporting. 

***

### Project Purpose

This project is both a personal learning tool and a practical log analysis pipeline. Security Log Analyzer is part of a personal portfolio to demonstrate log analysis, Ruby development, and security-focused 
data handling. The goal is to simplify the process of examining Linux 'auth.log' files, highlight time based patterns, and generate structured data for further use. 

***

### Project Structure
```
|── data/            # Sample log files
├── docs/            # Generated datasets and graphs
├── lib/             # Parsing and analyze classes
├── main.rb/         # Program main driver
├── README.md/       # Project overview
└── spec/            # RSpec unit tests
```

***

### Features
- Parse `auth.log` system logs for:
     - Error flags
     - Authentication failures
     - Invalid users
     - Failed password
     - Disconnects
     - Accepted publickey/passwords
     - Session open/closes
     - Sudo usage
- Basic event counting and grouping
- Hourly and daily breakdown of events
- Top 10 IP's connected to security events
- Tested with RSpec for reliability

***

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
- Results saved to
```
results/datasets/
results/graphs/
```

***

### Testing
- Run the RSpec test suite
```
bundle exec rspec
```
- Results saved to
```
results/tests/
```

***

### Sample Ouput

```
+----------------------------------------+
|         High Security Concerns         |
+--------------------------+-------------+
| Event Type               | Occurrences |
+--------------------------+-------------+
| Error Flags              | 189         |
| Authentication failures  | 673         |
| Invalid users            | 177         |
| Failed password attempts | 713         |
+--------------------------+-------------+
```

```
                      Top 10 IPs by High Security Event
                  ┌                                        ┐ 
    24.151.103.17 ┤■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 157   
   34.204.227.175 ┤■■■■■■■■■■■■■■■■■■■ 86                    
     49.4.143.105 ┤■■■■■■■■■■■■■ 60                          
   91.197.232.109 ┤■■■■■■■■■■■■■ 58                          
   201.178.81.113 ┤■■■■■■■■■ 40                              
   122.163.61.218 ┤■■■■■■■■ 38                               
    181.26.186.35 ┤■■■■■■■■ 36                               
    181.25.206.27 ┤■■■■ 16                                   
    14.54.210.101 ┤■■■ 14                                    
    85.245.107.41 ┤■■■ 13                                    
                  └                                        ┘ 
```

```
                     Sudo_command Event by Date
              ┌                                        ┐ 
   2025-03-27 ┤■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 77   
   2025-03-28 ┤■■■■■■■■■ 19                              
   2025-03-29 ┤■■■■■■ 12                                 
   2025-03-30 ┤ 1                                        
   2025-03-31 ┤■ 3                                       
   2025-04-01 ┤ 0                                        
   2025-04-02 ┤ 0                                        
   2025-04-03 ┤■■■■■■■■■■ 21                             
   2025-04-04 ┤ 0                                        
   2025-04-05 ┤ 0                                        
   2025-04-06 ┤ 0                                        
   2025-04-07 ┤ 0                                        
   2025-04-08 ┤ 0                                        
   2025-04-09 ┤■■■■■■■ 16                                
   2025-04-10 ┤■■■■■■■■■■■■■■■■■ 37                      
   2025-04-11 ┤ 0                                        
   2025-04-12 ┤ 0                                        
   2025-04-13 ┤ 0                                        
   2025-04-14 ┤ 0                                        
   2025-04-15 ┤ 0                                        
   2025-04-16 ┤ 0                                        
   2025-04-17 ┤ 0                                        
   2025-04-18 ┤ 0                                        
   2025-04-19 ┤ 0                                        
   2025-04-20 ┤ 0                                        
              └                                        ┘ 
```

```
             Invalid_user Event by Hour
      ┌                                        ┐ 
   00 ┤■ 1                                       
   01 ┤■■ 2                                      
   02 ┤■■ 2                                      
   03 ┤■ 1                                       
   04 ┤■■■■■ 6                                   
   05 ┤■■ 3                                      
   06 ┤■■■■■■■■■■■■■■■■■■■■■■■■■■ 33             
   07 ┤■■ 2                                      
   08 ┤■■ 2                                      
   09 ┤■■■■ 5                                    
   10 ┤■■ 2                                      
   11 ┤■■■ 4                                     
   12 ┤ 0                                        
   13 ┤ 0                                        
   14 ┤■■■■■■■ 9                                 
   15 ┤ 0                                        
   16 ┤■■ 2                                      
   17 ┤■■■■ 5                                    
   18 ┤■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 38         
   19 ┤■■ 3                                      
   20 ┤■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 45   
   21 ┤■■ 3                                      
   22 ┤■■■■■■ 7                                  
   23 ┤■■ 2                                      
      └                                        ┘ 
```
***

### Roadmap

- [x] Parse `auth.log` files
- [x] Event grouping by types and timestamps
- [x] Normalizes raw log data into structured formats to support automated analysis and reporting
- [ ] Integrate a Rails-based dashboard for data visualization (*In Progress*)
- [ ] Add additional analysis features 
    - [ ] User behaviour analysis
    - [ ] Failed login and brute-force detection
    - [ ] IP & host activity mapping
    - [ ] Command and activity correlation
    - [ ] Event frequency heatmaps
- [ ] Expand support for additional log formats (e.g., secure.log, syslog, cloud audit logs) 

***

### Author

Chris Skeens | 
[LinkedIn](https://www.linkedin.com/in/christopher-skeens-846780248/)

***

[![Ruby Style Guide](https://img.shields.io/badge/code_style-rubocop-brightgreen.svg)](https://github.com/rubocop/rubocop)
