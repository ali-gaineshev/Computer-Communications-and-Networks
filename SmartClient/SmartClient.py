#!/usr/bin/env python
import sys
import socket 
import re 
import ssl
import time as t
from typing import Tuple
from typing import List

"""
Assignment 1 for CSC 361. Connects to a server and send a http request. Receives it and prints out information about it
To use this program, run: python SmartClient.py \"link to a website\" .[Optional: prints html body]

Code author: Ali Gaineshev
"""

def parse_argument()->Tuple[str,str,int]:
    """
    Parses argument given to extract url, resource path and port(if any). Exists if less than 2 arguments are given. Ignores 3rd Optional argument
    @return: url, resource path, port number
    """
    if(len(sys.argv) < 2):
        print("To use this program, run: python SmartClient.py \"link to a website\" .[Optional: print html body]")
        exit(1)
    url: str = sys.argv[1]
    return parse_url(url)

def parse_url(url: str)->Tuple[str,str,int]:
    """
    Parses whole url to extract host name, resource path and port. Example: https://www.uvic:443.ca -> www.uvic.ca, /, 443
    @param: url to be parsed
    @returns: host name(url), resource path, port number
    """
    pattern: str = r'[a-z]+:(\d+)'
    match = re.search(pattern,url)
    #find port number and remove it first
    if match:
        port = int(match.group(1))
        url = re.sub(":" + str(port),'',url)

    else:
        port = None
    #check if url in argument starts with http(s) and remove it
    if(url.startswith("https://")):
        url = url[8:]
        port: int = 443 if port is None else port
    elif(url.startswith("http://")):
        url = url[7:]
        port: int = 80 if port is None else port

    #split on "/" to get resource path and right host name
    whole_url: List[str] = url.split("/")
    host_name: str = whole_url[0]
    if(len(whole_url) > 1):#resource path does exist
        resource_path:str = "/" + "/".join(whole_url[1:])
    else:# resource path is "/" if empty
        resource_path:str  = "/"

    host_name = host_name.strip()
    resource_path = resource_path.strip()
    return host_name, resource_path,port 

def get_ip(url: str)-> int:
    """
    Gets the IP address for the given url. If can't be found then exits
    
    @param: url (str): The URL for which to retrieve the IP address.
    @returns: str The IP address.
    """
    try:
        ip: int = socket.gethostbyname(url)
    except:
        print("Error with getting ip of the website")
        exit(1)
    return ip

def reconfigure_socket(new_url: str, new_port: int, http2: bool)-> Tuple[socket.socket, bool]:
    """
    Resets the socket for redirects. Exceptions might be thrown
    @param: url: str, port: int, http2:bool
    @returns: new socket, boolean if http2 was supported
    """
    s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip: int = get_ip(new_url)
    http2: bool
    s, http2 = make_connection(s, new_port, new_url, ip, http2)
    return s,http2

def parse_cookies(cookies_raw: List[str]) -> List[str]:
    """
    Parses a list of raw cookie strings into a list of formatted cookie strings.
    
    @param: cookies_raw (list[str]): A list of raw cookie strings.
    @return: list[str] A list of formatted cookie strings.
    """
    cookie_name: bool = True #first component in the string is assumed to be the cookie name
    parsed_cookies: List[str] = [] 
    for raw_cookie in cookies_raw:
        cookie_item: str = "cookie name: "
        attr: List[str] = raw_cookie.split("; ")#split all of the componenets 

        for component in attr:
            items: List[str] = component.split("=")#check the ones that have = in it
            if(len(items) > 1):# if length more than 2 then there was = sign and we are interested in it
                if(cookie_name == True):# first one is assument to be cookie name
                    cookie_item += items[0]
                    cookie_name = False
                else:
                    if(items[0].lower() == 'expires'):#expiration
                        cookie_item += ", expires time: " + items[1]

                    if(items[0].lower() == 'domain'):#domain
                        cookie_item += ", domain name: " + items[1]
        cookie_name = True
        parsed_cookies.append(cookie_item)
            
    return parsed_cookies

def send_and_receive(s: socket.socket, http_request: str) -> str:
    """
    Sends an HTTP request and receives the response.
    @param: s (socket.socket) The socket to use for the connection.
            http_request (str)  The HTTP request to send. Not encoded
    
    @returns: str The decoded response data.
    """
    print("\n----HTTP request----\n\n"+http_request)
    s.sendall(http_request.encode())

    print("----Request end----\n\nHttp request sent, started retrieving data... ", end = " |  ")
    response: bytes = b""
    s.settimeout(5)  # Set a timeout. This is done because some servers might still try to get data, but there is none to be recieved
    try:
        while True:
            data = s.recv(4096)
            if len(data) == 0:
                break
            response += data
    except socket.timeout:
        print("Socket timeout. Stopped retrieving data manually")
    except Exception as e:
        print(f"Couldn't receive data, something went wrong. Exitting... The erros is:\n{e}")
    else:
        print("Stopped retrieving data")
    finally:
        s.settimeout(None) 

    try:
        decoded_data = response.decode()#utf-8
    except UnicodeDecodeError:
        try:
            decoded_data = response.decode('ISO-8859-1')#google uses this one
        except UnicodeDecodeError:
                print("Couldn't decode the message")
                exit(1)

    return decoded_data

def send_request_rec(s: socket.socket, url: str, resource_path: str, port: int, http2: bool = False, n: int = 1) -> Tuple[List[str], bool, bool]:
    """ Sends a recursive HTTP request and handles redirects and some codes
    
    @param
        s (socket.socket) The socket to use for the connection.
        url/host name (str) The URL to send the request to.
        resource_path (str) The resource path of the URL.
        port (int) The port to use for the connection.
        http2 (bool, optional) Whether http2 is supported. If true then unaffected. Defaults to False.
        n (int, optional): The recursion number. Defaults to 1.
    
    @returns:
        Tuple[list[str], bool, bool]: A tuple containing the response, bool whether http2 is supported, and bool whether the resource is protected.
    """
    print("\n" + "*" * 30 + f" Recursion number {n} " + "*" * 30 )
    #http_request = f"GET {resource_path} HTTP/1.1\r\nHost: {url}\r\nConnection: keep-alive\r\n\r\n"
    http_request: str = f"GET {resource_path} HTTP/1.1\r\nHost: {url}\r\n\r\n"
    decoded_data: str = send_and_receive(s, http_request)
    response_lines: List[str] = decoded_data.split("\n")
    new_url = None
    protected: bool = False

    if(len(response_lines) == 0):
        print("Something went wrong on the request. Got empty response")
        return [], False, False

    if any(code in response_lines[0] for code in ["404", "200","403"]):# Forbidden, Ok, Restricted
        return response_lines, http2, protected
    
    if any(code in response_lines[0] for code in ["401"]):#Protected website
        protected = True
        return response_lines, http2, protected
    
    if any(code in response_lines[0] for code in ["301","302"]):# Redirects
        new_url = None

    if any(code in response_lines[0] for code in ["100","101","400","500","501","502","503","504","505"]):#Unhandled codes.
        print("\nUnhandled code received!\n")
        print(response_lines[0])
        exit(1)
        #return response_lines, http2, protected

    #Handle redirects
    for line in response_lines:
        
        if "Location" in line and new_url is None:
            new_url: str = line.split(": ")[1].strip()

        if new_url:
            new_resource_path: str
            new_port: int
            new_url,new_resource_path, new_port = parse_url(new_url)
            
            if(new_url == url and resource_path == new_resource_path):
                print("Website redirected to itself. Trying again")

            print(f"Redirecting to url: {new_url}{new_resource_path}")
            
            #After this the socket would be closed and remade again for redirection
            s.close()
            s, new_http2 = reconfigure_socket(new_url, new_port, http2)
            print("HTTTP2---------",new_http2)
            return send_request_rec(s, new_url,new_resource_path, new_port, new_http2, n+1)#recursive, sends new requests
        
    #Shouldn't reach this at any point
    print("Something went wrong. Shouldn't be here")

def make_connection(s: socket.socket, port: int, url: str, ip: int, http2: bool = False)-> Tuple[socket.socket, bool]:
    """ This function tries to establish a connection to a server, based on the port. If port is not specified
        then port 80 is default (HTTP). If port is 443 it will check if http2 was checked beefore(False). If not 
        it will try to connect using http2. If it's supported then it makes a new socket again. If http2 is already true
        then it will not try to reconnect

        @param:
        s (socket.socket) The socket to use for the connection.
        port (int) The port to use for the connection.
        url/host name (str) The URL to send the request to.
        ip (int) the ip address of the server
        http2 (bool, optional) Whether http2 is supported. If true then unaffected. Defaults to False.
    
    """
    try:    
        if port == 443:
            context = ssl.create_default_context()
            if(http2 == False): #http2 was not checked or failed
                context.set_alpn_protocols(['h2']) 
            s = context.wrap_socket(s, server_hostname=url)
        elif port is None:
            port = 80  #default port if not specified

        s.settimeout(3)
        s.connect((ip, port))
        s.settimeout(3)

        if port == 443 and http2 == False: #protocols are set to h2, so check if it's true
            negotiated_protocol = s.selected_alpn_protocol()
            if negotiated_protocol == 'h2':# protocols is set h2, so the response will be received as in frames, so have to restart the socket
                http2 = True
                
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                context = ssl.create_default_context()
                s = context.wrap_socket(s, server_hostname=url)
                s.connect((ip,port))
        
            print("Connected to https (443)")
        else:# otherwise connect normal (even 443 (https))
            print(f"Connected to http ({port})")

    except (ssl.SSLError, socket.error, socket.gaierror, socket.timeout, ssl.CertificateError):
        print("Could not connect to the server.")
        exit(1)

    return s,http2

def print_summary(url: str, protected: bool, http2: bool, cookies_raw: List[str]) -> None:
    """
    This function prints summary of results gotten at the end
    @param: url (str) host name of the website
            protected (bool) whether the url is protected (404 code)
            http2 (bool) whether the url supports http2
            cookies_raw (list) list of cookies as unparsed string
    """
    cookies: List[str] = []
    protected_response: str = "yes" if protected == True else "no"
    print("_" * 90)
    print(f"Summary:\n\nwebsite: {url}")
    print("1. Supports http2: ",end = "")

    if(http2 == True):
        print("yes")
    else:
        print("no")

    print("2. List of cookies: ")
    if(len(cookies_raw) == 0):
        print("None")
    else:
        cookies = parse_cookies(cookies_raw)
        for cookie in cookies:
            print(cookie)

    print(f"3. Protected: {protected_response}")
    print("_" * 90)

def smart_client()-> None:
    """
    Main function of the code. Makes first socket, and starts sending data. After receiving data prints it out
    """
    html_body: bool = False
    if(len(sys.argv) == 3):# Optional argument. if it's . then prints out html body
        if(sys.argv[2] == '.'):
            html_body = True

    url: str
    resource_path: str
    port: int

    url,resource_path, port  = parse_argument()
    http2 :bool = False
    ip: int = get_ip(url)
    print("Url: " + url)
    print("Resource path: " + resource_path)
    print("Port: ", port)
    print("Ip: " + ip)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print ("Socket was created successfully")

    except socket.error:
        print (f"Failed to create a socket.\nError: {socket.error}")
    
    s,http2 = make_connection(s, port, url, ip)# makes connection. ALso checks if http2 is supported
    try:
        response : List[str]
        confirmed_http2: bool
        protected: bool

        response, confirmed_http2, protected = send_request_rec(s,url, resource_path,port, http2, 1)# send requests
    except Exception as e:
        print(f"\nReceived an error.\n {e}")
        exit(1)

    cookies_list: List[str] = []
    print("\n--Response Header--\n")
    
    #print out the response
    if(response is not None):
        for line in response:
            if("Set-Cookie" in line):# add raw cookies
                cookies_list.append(line.split(": ")[1])
            if(any(body in line for body in ["<!DOCTYPE", "<!doctype", "<head", "<html>"])):# check if html body is started
                if(html_body == False):# html body is unwanted so break
                    break
            print(line)
    else:
        print("Response is empty. Exiting...")
        exit(1)
    
    print_summary(url, protected, (http2 if http2 == True else confirmed_http2), cookies_list)


if __name__ == '__main__':
    start_t: int = t.time()
    smart_client()#main code
    end_t: int = t.time()
    print("Code ran for: " + str(end_t - start_t) + " seconds")
