# Shared constants for the LanDrop application

# --- Application Identification ---
APP_NAME = "LanDrop"
SERVICE_TYPE = "_landrop._tcp.local." # Zeroconf service type

# --- Networking ---
APP_PORT = 56789 # Default TCP port for transfers

# --- Protocol Transfer Types ---
TRANSFER_TYPE_FILE = "FILE"               # Single file transfer
TRANSFER_TYPE_TEXT = "TEXT"               # Text snippet transfer
TRANSFER_TYPE_MULTI_START = "MULTI_START" # Start of multi-file/folder batch
TRANSFER_TYPE_MULTI_FILE = "MULTI_FILE"   # Header for an individual file within a batch
TRANSFER_TYPE_MULTI_END = "MULTI_END"     # End of multi-file/folder batch

# --- Protocol Signals ---
TRANSFER_TYPE_ACCEPT = "ACCEPT"           # Receiver confirms readiness/acceptance
TRANSFER_TYPE_REJECT = "REJECT"           # Receiver rejection signal
ACK_BYTE = b'\x06'                       # Acknowledgement byte for multi-file sync (ASCII ACK)

# --- Configuration ---
CONFIG_DIR_NAME = APP_NAME                 # Folder name within user config (e.g., ~/.config/LanDrop)
CONFIG_FILE_NAME = "config.ini"            # Name of the configuration file
DEFAULT_DOWNLOADS_DIR_NAME = "Downloads"   # Default directory name to search for downloads

# --- TLS Security (Certificates) ---
CERT_DIR_NAME = "certs"                    # Subdirectory name for TLS certificates (relative to config file)
CERT_FILE_NAME = "landrop_cert.pem"        # Default certificate filename
KEY_FILE_NAME = "landrop_key.pem"          # Default private key filename