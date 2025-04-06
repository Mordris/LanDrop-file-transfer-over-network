import json
import struct
import socket
import sys
import ssl # Needed for potential SSLError

# Use constants
try:
    from ..utils.constants import (TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT, TRANSFER_TYPE_ACCEPT,
                            TRANSFER_TYPE_REJECT)
except ImportError: # Fallback for potential direct execution or import issues
    TRANSFER_TYPE_FILE = "FILE"
    TRANSFER_TYPE_TEXT = "TEXT"
    TRANSFER_TYPE_ACCEPT = "ACCEPT"
    TRANSFER_TYPE_REJECT = "REJECT"


HEADER_LENGTH_FORMAT = "!I"  # 4 bytes, Network byte order (Big Endian), Unsigned Integer
HEADER_ENCODING = 'utf-8'

# --- Header Creation Functions ---

def _create_base_header(transfer_type: str, payload_size: int, metadata: dict = None) -> bytes:
    """Internal helper to create header dict, JSON, and prefix length."""
    header_dict = {
        'transfer_type': transfer_type,
        'data_size': int(payload_size), # Ensure it's an integer
        'metadata': metadata if metadata is not None else {} # Ensure metadata exists, allow None explicitly
    }
    try:
        header_json = json.dumps(header_dict).encode(HEADER_ENCODING)
        header_length = len(header_json)
        packed_length = struct.pack(HEADER_LENGTH_FORMAT, header_length)
        return packed_length + header_json
    except (TypeError, json.JSONDecodeError) as e:
        print(f"Error creating header JSON: {e}")
        raise ValueError(f"Cannot serialize header: {header_dict}") from e


def create_file_header(filename: str, filesize: int) -> bytes:
    """Creates header for single file transfer."""
    metadata = {
        'filename': filename,
        'source_os': sys.platform # Add basic OS info
        }
    return _create_base_header(TRANSFER_TYPE_FILE, filesize, metadata)

def create_text_header(text_payload: bytes) -> bytes:
    """Creates header for text transfer. Payload is text bytes."""
    # Metadata might not be needed for simple text, but keep structure consistent
    return _create_base_header(TRANSFER_TYPE_TEXT, len(text_payload), {})

def create_reject_header(reason: str = "Rejected by user") -> bytes:
     """Creates header to signal rejection."""
     metadata = {'reason': reason}
     return _create_base_header(TRANSFER_TYPE_REJECT, 0, metadata)

def create_accept_header() -> bytes:
     """Creates header to signal acceptance."""
     metadata = {'message': 'Ready to receive'} # Optional message
     return _create_base_header(TRANSFER_TYPE_ACCEPT, 0, metadata)

# --- Header Parsing Function ---

def read_exact(sock: socket.socket, num_bytes: int) -> bytes | None:
    """Reads exactly num_bytes from the socket, handling short reads."""
    data = b''
    while len(data) < num_bytes:
        try:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                # Connection closed prematurely
                return None
            data += chunk
        except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            # Timeout or non-blocking SSL operation, caller should handle/retry
            # For blocking sockets, timeout is the main concern here.
            # Return partial data or None? Let's return None on timeout/closure.
             print("Socket timeout or closed while reading exact bytes.")
             return None
        except (socket.error, ssl.SSLError) as e:
             print(f"Socket/SSL error reading exact bytes: {e}")
             raise # Re-raise socket/SSL errors for higher level handling
    return data


def parse_header(sock: socket.socket, timeout: float = 10.0) -> dict | None:
    """Reads the header length, then the header JSON from the socket."""
    original_timeout = None
    try:
        # Set timeout for the whole header read operation
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)

        # 1. Read Header Length (4 bytes) using helper
        packed_len = read_exact(sock, struct.calcsize(HEADER_LENGTH_FORMAT))
        if packed_len is None:
            # Error or closure handled within read_exact
            return None

        header_length = struct.unpack(HEADER_LENGTH_FORMAT, packed_len)[0]

        # Sanity check length
        if header_length <= 0 or header_length > 2 * 1024 * 1024: # Allow slightly larger headers (2MB limit)
             print(f"Invalid header length received: {header_length}. Closing connection.")
             return None

        # 2. Read Header JSON Data using helper
        header_json_bytes = read_exact(sock, header_length)
        if header_json_bytes is None:
             print("Failed to read header JSON data (connection closed or timeout).")
             return None

        # 3. Decode and Parse
        header_json = header_json_bytes.decode(HEADER_ENCODING)
        header_dict = json.loads(header_json)

        # Basic validation of required fields
        if not isinstance(header_dict, dict) or \
           not all(k in header_dict for k in ('transfer_type', 'data_size', 'metadata')):
            print(f"Malformed header received (missing keys or not dict): {header_dict}")
            return None

        # Further validation? E.g., check data_size is non-negative int
        if not isinstance(header_dict.get('data_size'), int) or header_dict['data_size'] < 0:
            print(f"Invalid data_size in header: {header_dict.get('data_size')}")
            return None

        return header_dict

    except (struct.error, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Header parsing/decoding error: {e}")
        return None
    except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
        # Should be caught by read_exact, but handle here just in case
        print(f"Socket timeout ({timeout}s) during header parsing.")
        return None
    except (socket.error, ssl.SSLError) as e:
        # Catch errors raised by read_exact or during parsing setup
        print(f"Socket/SSL error during header parsing: {e}")
        return None
    except Exception as e:
        # Catch unexpected errors during parsing
        print(f"Unexpected error parsing header: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Restore original timeout if possible
        if original_timeout is not None and hasattr(sock, 'settimeout'):
             try:
                  # Check if socket is still usable before setting timeout
                  # This check is tricky and platform dependent, maybe just try/except
                  sock.settimeout(original_timeout)
             except (OSError, socket.error, ssl.SSLError):
                  # Socket might already be closed or in error state
                  pass