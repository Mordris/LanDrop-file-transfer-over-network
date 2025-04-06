# Shared constants for the LanDrop application

APP_NAME = "LanDrop"
SERVICE_TYPE = "_landrop._tcp.local."
APP_PORT = 56789 # Default TCP transfer port
DEFAULT_DOWNLOADS_DIR_NAME = "Downloads" # Used by config manager

# Configuration file details
CONFIG_DIR_NAME = APP_NAME # Folder name within user config (e.g., ~/.config/LanDrop)
CONFIG_FILE_NAME = "config.ini"

# Protocol constants
TRANSFER_TYPE_FILE = "FILE"
TRANSFER_TYPE_TEXT = "TEXT"
TRANSFER_TYPE_MULTI_START = "MULTI_START" # For multi-file
TRANSFER_TYPE_MULTI_FILE = "MULTI_FILE"   # For multi-file
TRANSFER_TYPE_MULTI_END = "MULTI_END"     # For multi-file
TRANSFER_TYPE_REJECT = "REJECT"           # For receiver rejection (optional)

# TLS constants (Basic - for self-signed certs)
CERT_DIR_NAME = "certs" # Subdirectory for certs
CERT_FILE_NAME = "landrop_cert.pem"
KEY_FILE_NAME = "landrop_key.pem"