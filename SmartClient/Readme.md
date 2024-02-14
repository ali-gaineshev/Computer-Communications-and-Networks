# SmartClient - HTTP Client for server connection, sending request and receiving response
This is a Python3 script made to connect to a server, send an HTTP request, receive a response, and print information about the response. Additionally it checks for:

* Whether website supports http2
* Cookies information
* If website is password protected

# Usage

To use this program, follow these steps:

1. Open your terminal or command prompt.

2. Navigate to the directory containing the `SmartClient.py` file.

3. Run the following command:
   ```
   python3 SmartClient.py "link to a website" "." [Optional: print html body]
   ```
  "link to a website": Replace this with the URL of the website you want to connect to. General outline - protocol://host[:port]/resource_path
  "." [Optional: print html body]: This is an optional argument. If you include a period (.) as the second argument, the script will print the HTML body of the response.
   - the rest of the arguments are ignored

Example usage:
```
python3 SmartClient.py https://www.example.com .
python3	SmartClient.py www.uvic:443.ca 
```

Author - Ali Gaineshev

Packages/libraries used. All are part of Python's standard library: 
sys
socket 
re 
ssl
time
typing

Sample output:
![alt text](<../readme_images/Screenshot from 2024-02-14 12-31-28.png>)