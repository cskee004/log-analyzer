# Security Log Analyzer

### Acknowledgements
This project uses log data from [Machine Learning/Security Analytics Recipes/suspicious_login_activity/data/auth.log](https://github.com/elastic/examples) by Elastic, licensed under the Apache License 2.0.  
Original dataset: [auth.log](https://github.com/elastic/examples/blob/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log)  
Modifications: [test-auth.log](https://github.com/cskee004/log-analyzer/blob/main/data/auth-test.log).


### Description
This is a ruby script that scans system logs for failed-login attempts, brute-force attacks, and suspicious activity. Results from the scan are then converted into two different inverted indexes for analysis. 

The first index maps security keywords to line numbers in the log. 
```
{
  "failed_password": [3, 8, 15],
  "invalid_user": [7, 12],
  "root_access": [20]
}
```
The second index maps IP addresses to their related security incidents. 
```
{
  "192.168.1.50": {"failed_attempts": 10, "usernames": ["admin", "guest"]},
  "203.0.113.12": {"failed_attempts": 5, "usernames": ["root"]}
}
```
