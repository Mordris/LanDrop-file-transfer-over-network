import json
import struct
import socket
import sys

# Use constants
from ..utils.constants import (TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                        TRANSFER_TYPE_MULTI_START, TRANSFER_TYPE_MULTI_FILE,
                        TRANSFER_TYPE_MULTI_END, TRANSFER_TYPE_REJECT)

HEADER_LENGTH_FORMAT = "!I"  # 4 bytes, Network byte order (Big Endian), Unsigned Integer
HEADER_ENCODING = 'utf-8'

# --- Header Creation Functions ---

def _create_base_header(transfer_type: str, payload_size: int, metadata: dict = None) -> bytes:
    """Internal helper to create header dict, JSON, and prefix length."""
    header_dict = {
        'transfer_type': transfer_type,
        'data_size': payload_size,
        'metadata': metadata if metadata else {} # Ensure metadata exists
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
    # Metadata might not be needed for simple text
    return _create_base_header(TRANSFER_TYPE_TEXT, len(text_payload), {})

def create_reject_header(reason: str = "Rejected by user") -> bytes:
     """Creates header to signal rejection."""
     metadata = {'reason': reason}
     return _create_base_header(TRANSFER_TYPE_REJECT, 0, metadata)


# --- Header Parsing Function ---

def parse_header(sock: socket.socket) -> dict | None:
    """Reads the header length, then the header JSON from the socket."""
    try:
        # 1. Read Header Length (4 bytes)
        packed_len = sock.recv(struct.calcsize(HEADER_LENGTH_FORMAT))
        if not packed_len:
            print("Connection closed while reading header length.")
            return None
        # Ensure we got exactly 4 bytes (can happen on non-blocking sockets, less likely here)
        while len(packed_len) < struct.calcsize(HEADER_LENGTH_FORMAT):
             chunk = sock.recv(struct.calcsize(HEADER_LENGTH_FORMAT) - len(packed_len))
             if not chunk:
                  print("Connection closed prematurely reading header length.")
                  return None
             packed_len += chunk

        header_length = struct.unpack(HEADER_LENGTH_FORMAT, packed_len)[0]

        # Sanity check length (e.g., less than 1MB to prevent memory issues)
        if header_length == 0 or header_length > 1024 * 1024:
             print(f"Invalid header length received: {header_length}. Closing connection.")
             return None


        # 2. Read Header JSON Data
        header_json_bytes = b''
        bytes_to_read = header_length
        while len(header_json_bytes) < bytes_to_read:
            chunk = sock.recv(bytes_to_read - len(header_json_bytes))
            if not chunk:
                print("Connection closed while reading header JSON.")
                return None
            header_json_bytes += chunk

        # 3. Decode and Parse
        header_json = header_json_bytes.decode(HEADER_ENCODING)
        header_dict = json.loads(header_json)

        # Basic validation of required fields
        if not all(k in header_dict for k in ('transfer_type', 'data_size', 'metadata')):
            print(f"Malformed header received (missing keys): {header_dict}")
            return None

        return header_dict

    except (struct.error, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Header parsing error: {e}")
        return None
    except socket.timeout:
        print("Socket timed out reading header.")
        return None
    except socket.error as e:
        print(f"Socket error reading header: {e}")
        return None
    except Exception as e:
        # Catch unexpected errors during parsing
        print(f"Unexpected error parsing header: {e}")
        return None