import re
from urllib.parse import urlparse

def defang_url(url: str) -> str:
    """
    Defangs a URL so it cannot be accidentally clicked:
    https://malicious.com/path -> hxxps://malicious[.]com/path
    """
    if not url:
        return ""
    
    # Replace protocol
    s = re.sub(r'^http://', 'hxxp://', url, flags=re.IGNORECASE)
    s = re.sub(r'^https://', 'hxxps://', s, flags=re.IGNORECASE)
    s = re.sub(r'^ftp://', 'fxp://', s, flags=re.IGNORECASE)
    
    # Defang host/dots in host
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            defanged_netloc = parsed.netloc.replace('.', '[.]').replace(':', '[:]')
            s = s.replace(parsed.netloc, defanged_netloc, 1)
        else:
            s = s.replace('.', '[.]')
    except Exception:
        s = s.replace('.', '[.]')
        
    return s

def refang_url(url: str) -> str:
    """
    Converts a defanged URL back to standard URL for external lookup.
    """
    if not url:
        return ""
    s = re.sub(r'^hxxps://', 'https://', url, flags=re.IGNORECASE)
    s = re.sub(r'^hxxp://', 'http://', s, flags=re.IGNORECASE)
    s = re.sub(r'^fxp://', 'ftp://', s, flags=re.IGNORECASE)
    s = s.replace('[.]', '.').replace('[:]', ':')
    return s

def defang_ip(ip: str) -> str:
    """
    Defangs an IPv4 or IPv6 address:
    192.168.1.1 -> 192[.]168[.]1[.]1
    """
    if not ip:
        return ""
    return ip.replace('.', '[.]').replace(':', '[:]')

def refang_ip(ip: str) -> str:
    """Refangs an IP address."""
    if not ip:
        return ""
    return ip.replace('[.]', '.').replace('[:]', ':')

def defang_domain(domain: str) -> str:
    """Defangs a domain: evil.com -> evil[.]com"""
    if not domain:
        return ""
    return domain.replace('.', '[.]')

def refang_domain(domain: str) -> str:
    if not domain:
        return ""
    return domain.replace('[.]', '.')

def defang_email(email_addr: str) -> str:
    """Defangs an email: user@evil.com -> user[@]evil[.]com"""
    if not email_addr:
        return ""
    return email_addr.replace('@', '[@]').replace('.', '[.]')

