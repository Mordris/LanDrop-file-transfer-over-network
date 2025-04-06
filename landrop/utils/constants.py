# Shared constants for the LanDrop application
import sys
import os # For checking environment variables on Android
from pathlib import Path # Needed for asset path resolution

# --- Application Identification ---
APP_NAME = "LanDrop"
SERVICE_TYPE = "_landrop._tcp.local." # Zeroconf service type

# --- Networking ---
APP_PORT = 56789 # Default TCP port for transfers
# Define a chunk size for splitting large files (e.g., 4MB)
# Adjust as needed based on testing and network conditions
CHUNK_SIZE = 4 * 1024 * 1024 # 4 MiB

# --- OS Identification for Discovery & UI ---
OS_NAME = sys.platform # e.g., 'win32', 'linux', 'darwin'
# Basic check for Android using system properties (may vary)
# More robust detection might be needed depending on the Android environment
if "ANDROID_STORAGE" in os.environ or "ANDROID_ROOT" in os.environ:
     OS_NAME = 'android'
# Note: iOS detection is difficult from standard Python

# --- Protocol Transfer Types ---
TRANSFER_TYPE_FILE = "FILE"               # Single file transfer (potentially chunked)
TRANSFER_TYPE_TEXT = "TEXT"               # Text snippet transfer
TRANSFER_TYPE_MULTI_START = "MULTI_START" # Start of multi-file/folder batch
TRANSFER_TYPE_MULTI_FILE = "MULTI_FILE"   # Header for an individual file/chunk within a batch
TRANSFER_TYPE_MULTI_END = "MULTI_END"     # End of multi-file/folder batch

# --- Protocol Signals ---
TRANSFER_TYPE_ACCEPT = "ACCEPT"           # Receiver confirms readiness/acceptance
TRANSFER_TYPE_REJECT = "REJECT"           # Receiver rejection signal
ACK_BYTE = b'\x06'                       # Acknowledgement byte for multi-file/chunk sync (ASCII ACK)

# --- Configuration ---
CONFIG_DIR_NAME = APP_NAME                 # Folder name within user config (e.g., ~/.config/LanDrop)
CONFIG_FILE_NAME = "config.ini"            # Name of the configuration file
DEFAULT_DOWNLOADS_DIR_NAME = "Downloads"   # Default directory name to search for downloads

# --- TLS Security (Certificates) ---
CERT_DIR_NAME = "certs"                    # Subdirectory name for TLS certificates (relative to config file)
CERT_FILE_NAME = "landrop_cert.pem"        # Default certificate filename
KEY_FILE_NAME = "landrop_key.pem"          # Default private key filename

# --- Assets ---
# Define relative directory and filenames for assets
ASSETS_DIR_NAME = "assets"
ICONS_SUBDIR_NAME = "icons"
APP_ICON_FILENAME_ICO = "LanDrop.ico" # For Windows iconbitmap
APP_ICON_FILENAME_PNG = "LanDrop.png" # For other platforms iconphoto

# OS Name mapping for icons (keys should match potential values of OS_NAME or os_info from discovery)
OS_ICON_MAP = {
    'win32': 'windows.png',
    'linux': 'linux.png',
    'darwin': 'macos.png', # For macOS
    'android': 'android.png',
    # 'ios': 'ios.png', # Add if iOS detection implemented
    'unknown': 'unknown.png' # Fallback icon
}