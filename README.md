## Security Log Analyzer

### Acknowledgements

Thank you to the [Elastic](https://github.com/elastic/examples/tree/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity) team for providing the dataset.

Original dataset: [auth.log](https://github.com/elastic/examples/blob/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log)  
Modifications: [test-auth.log](https://github.com/cskee004/log-analyzer/blob/main/data/auth-test.log)


### Description

This Ruby script scans Linux system logs to detect key security-related events, including error flags, authentication failures, disconnections, session activity, sudo command usage, successful logins, invalid user attempts, and failed password entries.

It analyzes these events to identify patterns such as failed login attempts, brute-force attacks, and other suspicious behavior. The results are then compiled into reports that summarize notable and potentially malicious activity across the system.

### Project Goal

The goal of this project is to provide a lightweight, scriptable tool for detecting and summarizing security-relevant activity on Linux systems. It supports system administrators and security analysts in quickly identifying threats such as unauthorized access attempts and suspicious behavior.

While the current version focuses on parsing and analyzing log files, future updates will include a persistent database and an interactive dashboard for exploring security events over time and across different systems.

