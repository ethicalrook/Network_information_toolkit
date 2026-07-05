import tldextract
import whois
import socket
import ipaddress


def domain_lookup(domain):                         #defined the function named domain lookup

    #extracting the domain from the user input    
    extracted = tldextract.extract(domain)

    #checking if the domain is valid or not
    is_valid = bool(extracted.domain and extracted.suffix)

    #condition if the domain is not valid then gives the output invalid domain and return nothing
    if not is_valid:
        print(f"invalid domain: {domain}")
        return False
    
    #if the domain is valid then in the try block
    try:

        #with the help of socket library retriving the ip string 
        ip_str = socket.gethostbyname(domain)

        #retriving the domain information in the variable domain_info with the help of whois library 
        domain_info = whois.whois(domain)

        print("=====================================================")
        print("           Network toolkit                           ")
        print("=====================================================")

        #printing the output
        print(f"Targeted domain: {domain}")
        print(f"IP address: {ip_str}")
        print(f"Registrar name: {domain_info.registrar}")

    #error handling
    except Exception as e:
        print(f"Domain lookup failed: {e}")
        return None
    
    #checking if the ip is private or public with the help of ipaddress library
    try:
        #converting ip string to an object
        ip = ipaddress.ip_address(ip_str)

        #if the ip is private then print ip status is private
        if ip.is_private:
            print("IP status: Private")
        else:
           print("Ip status: Public")

        #if the ip is not valid then valueerror
    except ValueError:  
        print("Invalid ip address")



# Retriving the input from the user
userdomain = input("enter your domain:")

# calling the function
domain_lookup(userdomain)


