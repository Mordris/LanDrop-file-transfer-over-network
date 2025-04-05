import json
import struct
import socket

HEADER_LENGTH_FORMAT = "!I"  # 4 bytes, Network byte order (Big Endian), Unsigned Integer
HEADER_ENCODING = 'utf-8'

def create_header(transfer_type: str, filename: str, data_size: int) -> bytes:
    """Creates the JSON header and prefixes it with its length."""
    header_dict = {
        'transfer_type': transfer_type, # e.g., "FILE"
        'metadata': {
            'filename': filename
        },
        'data_size': data_size
    }
    header_json = json.dumps(header_dict).encode(HEADER_ENCODING)
    header_length = len(header_json)
    # Pack length into 4 bytes, then prepend to the JSON header
    packed_length = struct.pack(HEADER_LENGTH_FORMAT, header_length)
    return packed_length + header_json

def parse_header(client_socket: socket.socket) -> dict | None:
    """Reads the header length, then the header JSON from the socket."""
    header_length_bytes = b''
    bytes_to_read = struct.calcsize(HEADER_LENGTH_FORMAT) # Should be 4

    # Read the exact number of bytes for the length prefix
    try:
        while len(header_length_bytes) < bytes_to_read:
            chunk = client_socket.recv(bytes_to_read - len(header_length_bytes))
            if not chunk:
                print("Error: Connection closed while reading header length.")
                return None
            header_length_bytes += chunk

        header_length = struct.unpack(HEADER_LENGTH_FORMAT, header_length_bytes)[0]
        # print(f"Debug: Received header length: {header_length}") # Debug

        # Now read the JSON header itself
        header_json_bytes = b''
        while len(header_json_bytes) < header_length:
            chunk = client_socket.recv(header_length - len(header_json_bytes))
            if not chunk:
                print("Error: Connection closed while reading header JSON.")
                return None
            header_json_bytes += chunk

        # Decode and parse the JSON
        header_json = header_json_bytes.decode(HEADER_ENCODING)
        header_dict = json.loads(header_json)
        # print(f"Debug: Received header dict: {header_dict}") # Debug
        return header_dict

    except (struct.error, json.JSONDecodeError, UnicodeDecodeError, socket.error) as e:
        print(f"Error parsing header: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error parsing header: {e}")
        return None