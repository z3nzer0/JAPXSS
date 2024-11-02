# JAPXSS

JAPXSS is a powerful tool designed to simplify the process of testing XSS payloads across multiple pages during web application penetration tests. It automates the verification to see if an XSS payload injected on one page is successfully reflected or executed on another page.

The tool is especially useful for scenarios where payload propagation needs to be checked across different endpoints in a web application.

# Features
- Automates cross-page XSS payload testing.
- Supports customizable request data, headers, and cookies.
- Offers multithreading for faster scans.
- Includes options for using proxies and saving output to a file.
- Adjustable sleep interval between requests for more precise testing.

# Command-Line Arguments
```

--urlPayload or -u: (Required) The base URL to send the payload.
--urlVuln or -v: (Required) The URL used to check for the presence of the payload.
--requestData or -d: Data used in the request (e.g., form data or query parameters).
--requestDataVuln: Data used in the request to check for vulnerability.
--injectParam or -j: (Required) The variable from requestData where the payload will be injected.
--wordlist or -w: (Required) The path to the wordlist to use for payloads.
--cookies or -c: Cookies to include in the request (e.g., session tokens).
--thread or -t: Number of threads to use for scanning, allowing faster execution.
--sleep or -s: Waiting time between sending the payload request and checking for vulnerability. Default is 1 second.
--output: File path to save the findings.
--proxy: Proxy address or URL for routing requests.
--quiet or -q: Suppresses the logo from being printed.
```

# Example Commands

```bash
# Basic Payload Test

python3 japxss.py -u "https://<YOUR_TARGET>/page1" -v "https://<YOUR_TARGET>/page2" -j name -w wordlist.txt

# Payload Test with Custom Data and Cookies

python3 japxss.py -u "https://<YOUR_TARGET>/page1" -v "https://<YOUR_TARGET>/page2" -d "param1=value1&param2=value2" -j param1 -w wordlist.txt --cookie "session=abcdef12345"

# Using a Proxy and Saving the Output

python3 japxss.py -u "https://<YOUR_TARGET>/page1" -v "https://<YOUR_TARGET>/page2" -j name -w wordlist.txt --proxy "http://127.0.0.1:8080" --output results.txt
```

