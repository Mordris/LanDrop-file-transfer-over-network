import socket

def get_local_ip_address():
    """Try to get the primary local IP address usable on the LAN."""
    # We want an address that other machines on the LAN can reach.
    # 127.0.0.1 is useless for this.
    ip_address = '127.0.0.1' # Default fallback
    try:
        # Try connecting to a public DNS server (doesn't actually send data)
        # This forces the OS to choose an appropriate outbound interface.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1) # Don't wait long
        s.connect(('8.8.8.8', 80)) # Google DNS, port 80
        ip_address = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Could not determine primary IP using external connect method: {e}. Trying hostname method.")
        # If external connect fails (e.g., no internet), try resolving local hostname
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            # Ensure it's not the loopback address if multiple IPs are configured
            if ip_address == '127.0.0.1':
                 # Try getting all IPs associated with the hostname
                 all_ips = socket.getaddrinfo(hostname, None)
                 for item in all_ips:
                     # Look for an IPv4 address that isn't loopback
                     if item[0] == socket.AF_INET and not item[4][0].startswith('127.'):
                         ip_address = item[4][0]
                         break
        except socket.gaierror as ge:
            print(f"Could not determine IP using hostname lookup: {ge}. Falling back to 127.0.0.1.")
            ip_address = '127.0.0.1' # Stick with fallback
        except Exception as ex:
            print(f"Unexpected error getting IP via hostname: {ex}. Falling back to 127.0.0.1.")
            ip_address = '127.0.0.1' # Stick with fallback


    # print(f"Debug: Determined local IP as: {ip_address}") # Debug
    return ip_address


def get_hostname():
    """Get the local hostname."""
    try:
        return socket.gethostname()
    except Exception as e:
        print(f"Error getting hostname: {e}. Using 'UnknownHost'.")
        return "UnknownHost"