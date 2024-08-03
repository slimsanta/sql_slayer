# sql_slayer
App which tests for sqli vulnerabilities

**Usage**
Make sure you install required libraries:
pip install requests beautifulsoup4 lxml

**Running the script**
python your_script_name.py http://example.com -t 10 -p http://proxyip:port

(-t indicates number of threads to use)
(-p proxy server to use is optional)

**config.json**
can be edited to add additional payloads
