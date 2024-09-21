import socket
import whois
import dns.resolver
import argparse

def domain_lookup(domain):
    """Resolve a domain to its IP address."""
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"{domain} -> {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"Error: Unable to resolve {domain}")
        return None

def reverse_dns(ip_address):
    """Perform a reverse DNS lookup."""
    try:
        domain = socket.gethostbyaddr(ip_address)
        print(f"{ip_address} -> {domain[0]}")
    except socket.herror:
        print(f"Error: Unable to perform reverse DNS lookup for {ip_address}")

def whois_lookup(domain):
    """Perform a WHOIS lookup for domain registration information."""
    try:
        domain_info = whois.whois(domain)
        print(f"WHOIS Info for {domain}:")
        print(domain_info)
    except Exception as e:
        print(f"Error performing WHOIS lookup for {domain}: {str(e)}")

def dns_records(domain):
    """Retrieve DNS records (NS, MX, TXT) for a domain."""
    record_types = ['NS', 'MX', 'TXT']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"\n{record_type} Records for {domain}:")
            for answer in answers:
                print(answer.to_text())
        except dns.resolver.NoAnswer:
            print(f"No {record_type} record found for {domain}.")
        except Exception as e:
            print(f"Error retrieving {record_type} record for {domain}: {str(e)}")

def export_results(domain, ip_address, whois_info, records):
    """Export results to a file."""
    with open(f"{domain}_lookup_results.txt", "w") as file:
        file.write(f"Domain: {domain}\n")
        file.write(f"IP Address: {ip_address}\n\n")
        file.write("WHOIS Information:\n")
        file.write(whois_info + "\n")
        file.write("\nDNS Records:\n")
        for record_type, record_data in records.items():
            file.write(f"{record_type} Records:\n{record_data}\n")

def show_banner():
    """Display a banner with author credits."""
    banner = """
    ****************************************
    *     Domain Lookup Tool v1.0          *
    *     Created by: It Is Unique Official *
    *     GitHub: https://github.com/itisuniqueofficial *
    ****************************************
    """
    print(banner)

def main():
    show_banner()

    parser = argparse.ArgumentParser(description="Advanced Domain Lookup Tool")
    parser.add_argument("domain", help="Domain name to look up (e.g., example.com)")
    parser.add_argument("--reverse", help="Perform reverse DNS lookup", action="store_true")
    parser.add_argument("--whois", help="Perform WHOIS lookup", action="store_true")
    parser.add_argument("--dns", help="Fetch DNS records (NS, MX, TXT)", action="store_true")
    parser.add_argument("--export", help="Export results to a file", action="store_true")
    
    args = parser.parse_args()
    domain = args.domain

    # Domain lookup
    ip_address = domain_lookup(domain)

    if ip_address and args.reverse:
        reverse_dns(ip_address)

    if args.whois:
        whois_info = whois_lookup(domain)

    if args.dns:
        dns_records(domain)

    # Export results if requested
    if args.export:
        whois_info_str = whois.whois(domain) if args.whois else ""
        dns_record_data = {
            'NS': "\n".join([str(answer) for answer in dns.resolver.resolve(domain, 'NS')]) if args.dns else "",
            'MX': "\n".join([str(answer) for answer in dns.resolver.resolve(domain, 'MX')]) if args.dns else "",
            'TXT': "\n".join([str(answer) for answer in dns.resolver.resolve(domain, 'TXT')]) if args.dns else ""
        }
        export_results(domain, ip_address, whois_info_str, dns_record_data)
        print(f"Results exported to {domain}_lookup_results.txt")

if __name__ == "__main__":
    main()
