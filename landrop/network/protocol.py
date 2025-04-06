import json
import struct
import socket
import sys
import ssl  # Needed for potential SSLError and constants
from pathlib import Path # For relative path type hint if needed elsewhere
import time # For drain delay (optional)
import traceback # For detailed unexpected errors

# Use constants
try:
    from ..utils.constants import (TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                            TRANSFER_TYPE_MULTI_START, TRANSFER_TYPE_MULTI_FILE,
                            TRANSFER_TYPE_MULTI_END,
                            TRANSFER_TYPE_ACCEPT, TRANSFER_TYPE_REJECT)
except ImportError: # Fallback for potential direct execution or import issues
    print("Warning (protocol.py): Failed to import constants from ..utils.constants. Using fallback values.")
    TRANSFER_TYPE_FILE = "FILE"
    TRANSFER_TYPE_TEXT = "TEXT"
    TRANSFER_TYPE_MULTI_START = "MULTI_START"
    TRANSFER_TYPE_MULTI_FILE = "MULTI_FILE"
    TRANSFER_TYPE_MULTI_END = "MULTI_END"
    TRANSFER_TYPE_ACCEPT = "ACCEPT"
    TRANSFER_TYPE_REJECT = "REJECT"


# --- Constants ---
HEADER_LENGTH_FORMAT = "!I"  # 4 bytes, Network byte order (Big Endian), Unsigned Integer
HEADER_ENCODING = 'utf-8'   # Encoding for JSON header content
HEADER_LEN_SIZE = struct.calcsize(HEADER_LENGTH_FORMAT) # Size of the length prefix (4 bytes)
MAX_HEADER_SIZE = 4 * 1024 * 1024 # 4 MB limit for header JSON size (generous)

# --- Header Creation Functions ---

def _create_base_header(transfer_type: str, payload_size: int, metadata: dict | None = None) -> bytes:
    """
    Internal helper to create header dict, serialize to JSON, and prefix with length.
    Handles potential serialization errors.
    """
    header_dict = {
        'transfer_type': transfer_type,
        # payload_size relevant for FILE, TEXT, MULTI_FILE. 0 for START, END, ACCEPT, REJECT.
        'data_size': int(payload_size), # Ensure integer type
        'metadata': metadata if metadata is not None else {} # Ensure metadata dict exists
    }
    try:
        # Serialize dictionary to JSON bytes
        header_json_bytes = json.dumps(header_dict).encode(HEADER_ENCODING)
        header_length = len(header_json_bytes)

        # Check if serialized header exceeds max allowed size
        if header_length > MAX_HEADER_SIZE:
             raise ValueError(f"Serialized header size ({header_length} bytes) exceeds maximum allowed ({MAX_HEADER_SIZE} bytes).")

        # Pack the length prefix (network byte order)
        packed_length = struct.pack(HEADER_LENGTH_FORMAT, header_length)

        # Return length prefix + JSON header content
        return packed_length + header_json_bytes

    except (TypeError, json.JSONDecodeError) as e:
        print(f"Error creating header JSON: {e}")
        # Raise a more specific error indicating serialization failure
        raise ValueError(f"Cannot serialize header data: {header_dict}") from e
    except ValueError as e: # Catch oversized header error
         print(f"Error: {e}")
         raise # Re-raise


def create_file_header(filename: str, filesize: int) -> bytes:
    """Creates header for single file transfer."""
    metadata = {
        'filename': filename,
        'source_os': sys.platform # Add basic OS info
        }
    return _create_base_header(TRANSFER_TYPE_FILE, filesize, metadata)

def create_text_header(text_payload: bytes) -> bytes:
    """Creates header for text transfer. Payload is the text content as bytes."""
    # Include OS info for consistency, payload size comes from text_payload length
    metadata = {'source_os': sys.platform}
    return _create_base_header(TRANSFER_TYPE_TEXT, len(text_payload), metadata)

def create_multi_start_header(total_items: int, total_size: int, base_name: str) -> bytes:
    """Creates header to start a multi-item transfer (files or folder)."""
    metadata = {
        'total_items': total_items,
        'total_size': total_size,
        'base_name': base_name, # e.g., folder name or "Multiple Files"
        'source_os': sys.platform
    }
    # data_size in base header is 0 for START signal itself
    return _create_base_header(TRANSFER_TYPE_MULTI_START, 0, metadata)

def create_multi_file_header(relative_path: str | Path, file_size: int) -> bytes:
    """Creates header for an individual file within a multi-item batch."""
    # Ensure relative_path is a string using POSIX style separators ('/')
    # for cross-platform compatibility on the receiving end.
    rel_path_str = str(Path(relative_path).as_posix())
    metadata = {
        'relative_path': rel_path_str,
        # 'file_size' is technically redundant (it's the main 'data_size'),
        # but keep for clarity or future protocol versions.
        # 'file_size': file_size
    }
    # The 'data_size' field holds the size of the upcoming file payload
    return _create_base_header(TRANSFER_TYPE_MULTI_FILE, file_size, metadata)

def create_multi_end_header() -> bytes:
    """Creates header to signal the end of a successful multi-item transfer."""
    metadata = {'message': 'Batch transfer complete'}
    return _create_base_header(TRANSFER_TYPE_MULTI_END, 0, metadata)

def create_reject_header(reason: str = "Rejected by user") -> bytes:
     """Creates header to signal rejection, with an optional reason."""
     metadata = {'reason': reason}
     return _create_base_header(TRANSFER_TYPE_REJECT, 0, metadata)

def create_accept_header() -> bytes:
     """Creates header to signal acceptance/readiness to receive."""
     metadata = {'message': 'Ready to receive'} # Optional message
     return _create_base_header(TRANSFER_TYPE_ACCEPT, 0, metadata)


# --- Header Parsing Functions ---

def read_exact(sock: socket.socket, num_bytes: int) -> bytes | None:
    """
    Reads exactly num_bytes from the socket.

    Handles short reads and socket/SSL errors including timeouts.
    Returns the data bytes if successful, None if connection closed or timeout occurs.
    Raises socket.error or ssl.SSLError for other connection issues.
    """
    data = b''
    if num_bytes <= 0: return data # Nothing to read

    try:
        # Loop until the desired number of bytes is received
        while len(data) < num_bytes:
            # Calculate remaining bytes to avoid over-reading if recv behaves unexpectedly
            bytes_to_read = num_bytes - len(data)
            chunk = sock.recv(bytes_to_read)

            if not chunk:
                # Socket connection was closed by the peer before all bytes were received
                print(f"Socket connection closed while trying to read {num_bytes} bytes (received {len(data)}).")
                return None # Indicate connection closed

            data += chunk

    except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
        # Timeout occurred during the recv call (based on socket's timeout setting)
        # or non-blocking SSL operation needs retry (less likely with blocking sockets)
        print(f"Socket timeout/SSLWant occurred while reading {num_bytes} bytes (received {len(data)}).")
        return None # Indicate timeout/SSL non-blocking state

    except (socket.error, ssl.SSLError) as e:
        # Catch other potential socket/SSL errors (e.g., connection reset)
        print(f"Socket/SSL error in read_exact while reading {num_bytes} bytes: {e}")
        raise # Re-raise the error for the caller to handle

    except Exception as e:
        # Catch any unexpected errors during the receive operation
        print(f"Unexpected error in read_exact: {e}")
        traceback.print_exc()
        raise # Re-raise

    # If loop completes, we have received the exact number of bytes
    return data


import json
import struct
import socket
import sys
import ssl  # Needed for potential SSLError and constants
from pathlib import Path # For type hints if needed
import time # No longer strictly needed here, but keep import if other parts use it
import traceback # For detailed unexpected errors

# Assuming constants like HEADER_LENGTH_FORMAT, HEADER_ENCODING,
# HEADER_LEN_SIZE, and MAX_HEADER_SIZE are defined above this function
# and the read_exact function is also defined above.

def parse_header(sock: socket.socket, timeout: float = 10.0) -> dict | None:
    """
    Reads the header length prefix, then the header JSON from the socket.

    Args:
        sock: The connected socket object (assumed to be blocking).
        timeout: Overall timeout in seconds for the entire header parsing operation.

    Returns:
        A dictionary representing the parsed header, or None if parsing fails,
        connection is closed, or timeout occurs.
    """
    original_timeout = None

    try:
        # Store original timeout and apply the specified overall timeout
        # This timeout applies to the combined duration of read_exact calls within this function.
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)

        # --- Socket Draining Removed ---

        # 1. Read Header Length Prefix (e.g., 4 bytes) using read_exact
        # read_exact will use the socket's current timeout (set above).
        # It returns None on timeout or clean connection closure.
        packed_len = read_exact(sock, HEADER_LEN_SIZE)
        if packed_len is None:
            # read_exact should have printed the specific reason (timeout or closure)
            print(f"Failed to read header length ({HEADER_LEN_SIZE} bytes).")
            return None # Indicate failure to read length

        # 2. Unpack Header Length
        try:
            # Use the defined format (e.g., "!I" for network byte order unsigned int)
            header_length = struct.unpack(HEADER_LENGTH_FORMAT, packed_len)[0]
        except struct.error as unpack_err:
            # This error occurs if packed_len is not the expected size or format
            print(f"Header length unpack error: {unpack_err}. Received raw bytes: {packed_len!r}")
            return None # Indicate failure due to malformed length bytes

        # 3. Sanity Check Header Length Value
        # Ensure length is positive and within reasonable limits to prevent OOM errors.
        if header_length <= 0 or header_length > MAX_HEADER_SIZE:
             print(f"Invalid header length value received: {header_length}. Max allowed: {MAX_HEADER_SIZE}. Raw length bytes: {packed_len!r}")
             # Don't attempt to read a potentially huge or invalid amount of data
             return None # Indicate failure due to invalid length value

        # 4. Read Header JSON Data using read_exact
        # Read the exact number of bytes specified by the unpacked header_length.
        header_json_bytes = read_exact(sock, header_length)
        if header_json_bytes is None:
             # read_exact should have printed the reason (timeout or closure)
             print(f"Failed to read header JSON data ({header_length} bytes).")
             return None # Indicate failure to read header content

        # 5. Decode and Parse JSON Header Content
        try:
            # Decode the received bytes using the specified encoding (e.g., utf-8)
            header_json = header_json_bytes.decode(HEADER_ENCODING)
            # Parse the JSON string into a Python dictionary
            header_dict = json.loads(header_json)
        except (UnicodeDecodeError, json.JSONDecodeError) as decode_err:
            # Handle errors if bytes are not valid UTF-8 or if JSON is malformed
            print(f"Header JSON decoding/parsing error: {decode_err}")
            # Log problematic bytes for debugging (limited length to avoid flooding logs)
            print(f"Problematic header bytes (first 100): {header_json_bytes[:100]!r}")
            return None # Indicate failure due to decoding/parsing error

        # 6. Basic Validation of Parsed Header Structure
        # Check if it's a dictionary and contains the minimum required keys.
        if not isinstance(header_dict, dict) or \
           not all(k in header_dict for k in ('transfer_type', 'data_size', 'metadata')):
            print(f"Malformed header received (missing essential keys or not a dictionary): {header_dict}")
            return None # Indicate failure due to incorrect structure

        # 7. Further Validation (Type/Value Checks)
        # Ensure 'data_size' is a non-negative integer.
        if not isinstance(header_dict.get('data_size'), int) or header_dict['data_size'] < 0:
            print(f"Invalid 'data_size' value in header: {header_dict.get('data_size')!r}")
            return None # Indicate failure due to invalid data_size

        # Optional: Add more specific validation based on 'transfer_type' if needed
        # e.g., check required metadata keys for MULTI_START / MULTI_FILE

        # 8. Success - Return Parsed Header Dictionary
        return header_dict

    # --- Outer Exception Handling ---
    except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
        # Catch timeout exceptions raised by read_exact or potentially other socket ops.
        print(f"Overall socket timeout ({timeout}s) occurred during header parsing.")
        return None # Indicate timeout failure
    except (socket.error, ssl.SSLError) as sock_err:
        # Catch connection errors (e.g., reset, broken pipe) raised by read_exact or socket ops.
        print(f"Socket/SSL connection error during header parsing process: {sock_err}")
        return None # Indicate connection error failure
    except Exception as e:
        # Catch any other unexpected errors during the parsing logic.
        print(f"Unexpected error parsing header: {e}")
        traceback.print_exc() # Log detailed traceback for unexpected errors
        return None # Indicate unexpected failure
    finally:
        # --- Restore Original Socket State ---
        # Restore the original socket timeout if it was changed.
        # Check if the socket object and original_timeout exist and the socket is still valid.
        if original_timeout is not None and sock and sock.fileno() != -1:
             try:
                  # Ensure socket is back in blocking mode (should be, but check)
                  if not sock.getblocking():
                       sock.setblocking(True)
                  # Restore the original timeout value
                  sock.settimeout(original_timeout)
             except (OSError, socket.error, ssl.SSLError, AttributeError):
                  # Ignore errors if socket is already closed or in an invalid state
                  pass