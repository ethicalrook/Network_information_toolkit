import tldextract as tl
import whois
import socket as sk
import ipaddress


def domain_lookup(domain):
    extracted = tl.extract(domain)

    is_valid = bool(extracted.domain and extracted.suffix)

    if not is_valid:
        print(f"invalid domain: {domain}")
        return False
    
    try:
        ip_str = sk.gethostbyname(domain)
        domain_info = whois.whois(domain)

        print("=====================================================")
        print("           Network toolkit                           ")
        print("=====================================================")

        print(f"Targeted domain: {domain}")
        print(f"IP address: {ip_str}")
        print(f"Registrar name: {domain_info.registrar}")

    except Exception as e:
        print(f"Domain lookup failed: {e}")
        return None
    
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.is_private:
            print("IP status: Private")
        else:
           print("Ip status: Public")

    except ValueError:  
        print("Invalid ip address")




userdomain = input("enter your domain:")
domain_lookup(userdomain)


