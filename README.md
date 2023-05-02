# DnsSec
- A DNS security audit tool is a software tool that checks a DNS server for security vulnerabilities and issues. It takes the DNS IP as user input and performs checks such as DNSSEC, cache snooping, DNS rebinding, DNS amplification, wildcard injections, NXDOMAIN attacks, DNS reflection, and open recursion. The tool can help identify potential security issues and improve the overall security and stability of the network.


## Installation

Install dnssec

```bash
  git clone https://github.com/themalwarenews/dnssec/
  cd dnssec
  python3 dnssec.py [ DNS_IP ] [ DOMAIN ]

  eg:
  python3 dnssec.py 9.9.9.9 iamsharan.com
```
    
    
