from pkgutil import resolve_name
from pydoc import resolve
import argparse
from types import resolve_bases
from xml.dom import DOMException
import dns.query
import dns.zone
import dns.resolver
import dns.exception
import socket
import random
import dns.resolver
from termcolor import colored
import string

# checking zone transfer
def check_zone_transfer(dns_ip, domain):
    try:
        zone = dns.zone.from_xfr(dns.query.inbound_xfr(dns_ip, domain))
        print(f"[WARNING] Zone transfer allowed on {dns_ip} for {domain}.")
    except DOMException as e:
        print(f"[INFO] Zone transfer not allowed on {dns_ip} for {domain}: {str(e)}")

# dnssec check
def dnssec_check(dns_ip,domain):
    print("\n")
    print("-"*100)
    print(colored("[+] Performing DNSSEC check...",'blue'))
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_ip]
        response = resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
        if response.rrset:
            print(colored(" 😁 DNSSEC is enabled:",'green'))
            for rdata in response:
                print(rdata)
                print("-"*100)
        else:
            print(colored(" 😞 DNSSEC is not enabled.",'red'))
            print("-"*100)
    except dns.resolver.NoAnswer:
        print(colored(" 🤦‍♂️ DNSSEC is not enabled.",'red'))
        print("-"*100)
    except Exception as e:
        print(colored(f" 😵‍💫 DNSSEC check failed: {e}",'red'))
        print("-"*100)

# checking cache snooping 
def cache_snooping_check(dns_ip,domain):
    print("-"*100)
    print(colored("[+] Performing Cache Snooping check...",'blue'))
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_ip]
    try:
        response = resolver.resolve(domain, 'A', raise_on_no_answer=False)
        if response.rrset:
            print(colored(" 😞 Cache Snooping successful:",'red'))
            for rdata in response:
                print(colored(rdata,'red'))
                print("-"*100)
        else:
            print(colored(" 😁 Cache Snooping not successful.",'green'))
            print("-"*100)
    except Exception as e:
        print(colored(f" 😵‍💫 Cache Snooping check failed: {e}",'red'))
        print("-"*100)

# checking for id hacking attack
def id_hacking_attack_check(dns_ip):
    print("-"*100)
    msg = dns.message.make_query(dns_ip, dns.rdatatype.A)
    msg.id = 666
    res = resolve_name.query(msg)
    if res.message.id == msg.id:
        print(colored(f' 🤦‍♂️ {resolve.nameservers[0]} is vulnerable to ID hacking attack','red'))
        print("-"*100)
    else:
        print(colored(f' 😁 {resolve_bases.nameservers[0]}  is not vulnerable to ID hacking attack','green')) 
        print("-"*100)

# checking dns_rebinding
def dns_rebinding_check(dns_ip,domain):
    print("-"*100)
    print(colored("[+] Performing DNS Rebinding check...",'blue'))
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_ip]
    try:
        response = resolver.resolve(domain, 'A', raise_on_no_answer=False)
        if response.rrset:
            for rdata in response:
                ip = str(rdata)
                if ip.startswith("127.") or ip.startswith("0."):
                    print(colored(f" 🤦‍♂️ DNS Rebinding detected: {ip} ",'red'))
                    print("-"*100)
                else:
                    print(colored(" 😁 DNS Rebinding not detected.",'green'))
                    print("-"*100)
        else:
            print(colored(" 😵‍💫 DNS Rebinding check not successful.",'green'))
            print("-"*100)
    except Exception as e:
        print(f" 😵‍💫 DNS Rebinding check failed: {e}")
        print("-"*100)

# checking dns amplification 
def dns_amplification_check(dns_ip,domain):
    print("-"*100)
    print(colored("[+] Performing DNS Amplification check...",'blue'))
    query = dns.message.make_query(domain, dns.rdatatype.ANY)
    query.flags |= dns.flags.AD
    query.find_rrset(query.additional, dns.name.root, 65535, dns.rdatatype.OPT, create=True, force_unique=True)
    try:
        response = dns.query.udp(query, dns_ip)
        if len(response.answer) > 0:
            amplification_factor = len(response.to_wire()) / len(query.to_wire())
            print(colored(f" 🤦‍♂️ DNS Amplification factor: {amplification_factor}",'red'))
            print("-"*100)
        else:
            print(colored(" 😁 DNS Amplification check not successful.",'green'))
            print("-"*100)
    except Exception as e:
        print(colored(f" 😵‍💫 DNS Amplification check failed: {e}",'red'))
        print("-"*100)

# checking generate random subdomains
def generate_random_subdomain(domain, length=10):
    random_str = ''.join(random.choices(string.ascii_lowercase, k=length))
    return f'{random_str}.{domain}'

# checking wildcard injections 
def wildcard_injections_check(domain):
    print("-"*100)
    print(colored("[+] Performing Wildcard Injections check...",'blue'))
    random_subdomains = [generate_random_subdomain(domain) for _ in range(3)]
    ips = set()
    for subdomain in random_subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            ips.add(ip)
        except socket.gaierror:
            pass
    if len(ips) > 1:
        print(colored(f" 🤦‍♂️ Wildcard injection detected for {domain}",'red'))
        print("-"*100)
        return True
    else:
        print(colored(f" 😁 No wildcard injection detected for {domain}",'green'))
        print("-"*100)
        return False
        

# checking nx domains
def nxdomain_attacks_check(domain):
    print("-"*100)
    print(colored("[+] Performing NXDOMAIN Attacks check..",'blue'))
    resolver = dns.resolver.Resolver()
    random_subdomain = generate_random_subdomain(domain)
    try:
        resolver.resolve(random_subdomain, 'A')
    except dns.resolver.NXDOMAIN:
        print(colored(f" 😁 No NXDOMAIN attack detected for {domain}",'green'))
        print("-"*100)
        return False
    except dns.resolver.NoAnswer:
        print(colored(f" 🤦‍♂️ NXDOMAIN attack detected for {domain}",'red'))
        print("-"*100)
        return True
    except dns.resolver.Timeout:
        print(colored(f"DNS query timed out for {domain}",'red'))
        print("-"*100)
        return False
    except Exception as e:
        print(f"Error: {e}")
        print("-"*100)
        return False
        

# checking dns reflection
def dns_reflection_check(dns_ip,domain):
    print("-"*100)
    print(colored("[+] Performing DNS Reflection check...",'blue'))
    query = dns.message.make_query(domain, dns.rdatatype.A)
    query.flags |= dns.flags.AD
    query.find_rrset(query.additional, dns.name.root, 65535, dns.rdatatype.OPT, create=True, force_unique=True)
    try:
        response = dns.query.udp(query, dns_ip)
        if len(response.answer) > 0:
            print(colored(" 😞 DNS Reflection detected:",'red'))
            for rdata in response.answer:
                print(colored(rdata,'red'))
                print("-"*100)
        else:
            print(colored(" 😁 DNS Reflection not detected.",'green'))
            print("-"*100)
    except Exception as e:
        print(colored(f"😵‍💫 DNS Reflection check failed: {e}",'red'))
        print("-"*100)

# checking open recursion
def open_recursion_check(server):
    print("-"*100)
    print(colored("[+] Performing Open Recursion check...",'blue'))
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]

    try:
        answers = resolver.resolve('version.bind', 'TXT')
        if answers.response.answer:
            print(colored(f" 😞 Open recursion detected on {server}",'red'))
            print("-"*100)
            return True
        else:
            print(colored(f" 😁 No open recursion detected on {server}",'green'))
            print("-"*100)
            return False
    except dns.resolver.NXDOMAIN:
        print(colored(f" 😁 Server {server} does not support version.bind",'red'))
        print("-"*100)
        return False
    except dns.resolver.Timeout:
        print(colored(f" 😁 DNS query timed out for {server}",'red'))
        print("-"*100)
        return False
    except Exception as e:
        print(colored(f"Error: {e}",'red'))
        return False


def main():
    parser = argparse.ArgumentParser(description='DNS Security Assessment Tool')
    parser.add_argument('dns_ip', help='DNS IP address to assess')
    parser.add_argument('domain', help='domain to assess along with')
    args = parser.parse_args()

    dns_ip = args.dns_ip
    domain =  args.domain
    #check_zone_transfer(dns_ip,domain)
    dnssec_check(dns_ip,domain)
    cache_snooping_check(dns_ip,domain)
    #id_hacking_attack_check(dns_ip)
    dns_rebinding_check(dns_ip,domain)
    dns_amplification_check(dns_ip,domain)
    wildcard_injections_check(dns_ip)
    nxdomain_attacks_check(dns_ip)
    dns_reflection_check(dns_ip,domain)
    open_recursion_check(dns_ip)

if __name__ == '__main__':
    main()
