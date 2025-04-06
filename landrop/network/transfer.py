import socket
import threading
import os
import time
import ssl
from queue import Queue, Empty
from pathlib import Path

# Relative imports
from .protocol import (create_file_header, create_text_header, create_reject_header,
                      parse_header, HEADER_ENCODING)
from ..utils.file_utils import generate_unique_filepath, ensure_certificates
from ..utils.config_manager import ConfigManager
from ..utils.constants import (APP_PORT, TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                        TRANSFER_TYPE_REJECT, CERT_DIR_NAME, CERT_FILE_NAME, KEY_FILE_NAME)

BUFFER_SIZE = 4096 * 16
PROGRESS_UPDATE_INTERVAL = 0.25

# --- TLS Context Setup ---
def create_ssl_context(cert_dir: Path, key_file: Path, cert_file: Path, server_side: bool = False) -> ssl.SSLContext | None:
    """Creates SSL context for server or client."""
    if not ensure_certificates(cert_dir, key_file, cert_file):
        print("Cannot proceed without TLS certificates.")
        return None

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
        # Load cert/key
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        if not server_side:
            # Client: Trust the self-signed cert (INSECURE FOR PRODUCTION)
            context.check_hostname = False # Disable hostname check for self-signed
            context.verify_mode = ssl.CERT_NONE # Do not verify the server cert chain
            print("TLS Client: WARNING - Server certificate verification is disabled (using self-signed certs).")
        else:
            # Server: Doesn't need to verify client unless client certs required (not implemented)
             print("TLS Server: Context created.")

        # Improve security settings (optional but recommended)
        # context.minimum_version = ssl.TLSVersion.TLSv1_2 # Set minimum TLS version

        return context
    except ssl.SSLError as e:
        print(f"SSL Error creating context: {e}")
    except FileNotFoundError:
        print(f"Certificate or Key file not found ({cert_file}, {key_file})")
    except Exception as e:
         print(f"Unexpected error creating SSL context: {e}")
    return None


class TransferAgent:
    """Base class for Sender/Receiver with common methods."""
    def __init__(self, status_queue: Queue, cancel_event: threading.Event):
        self.status_queue = status_queue
        self.cancel_event = cancel_event

    def _send_status(self, *args):
        if self.status_queue:
            try:
                self.status_queue.put(args)
            except Exception as e:
                print(f"Error sending status to queue: {e}")

    def _check_cancel(self):
        """Checks if cancellation has been requested."""
        if self.cancel_event and self.cancel_event.is_set():
            raise InterruptedError("Transfer cancelled by user.")

# --- File Sender ---
class FileSender(TransferAgent):
    """Handles sending a single file or text snippet to a peer."""
    def __init__(self, host: str, port: int, item: str, item_type: str, # item is filepath or text
                 status_queue: Queue, cancel_event: threading.Event,
                 use_tls: bool, ssl_context: ssl.SSLContext | None):
        super().__init__(status_queue, cancel_event)
        self.host = host
        self.port = port
        self.item = item # Filepath or text content
        self.item_type = item_type # TRANSFER_TYPE_FILE or TRANSFER_TYPE_TEXT
        self.use_tls = use_tls
        self.ssl_context = ssl_context
        self.filename = os.path.basename(item) if item_type == TRANSFER_TYPE_FILE else "text_snippet.txt" # Default name for text

    def _send_payload(self, sock: socket.socket, payload_source, payload_size: int):
        """Sends either file or text payload with progress."""
        bytes_sent = 0
        start_time = time.monotonic()
        last_update_time = start_time

        try:
            # Determine if source is a file path or bytes/string
            is_file = isinstance(payload_source, str) and os.path.exists(payload_source)

            if is_file:
                file_handle = open(payload_source, 'rb')
            elif isinstance(payload_source, bytes):
                 # For sending raw bytes (like text)
                 from io import BytesIO
                 file_handle = BytesIO(payload_source)
            else:
                 raise TypeError("Invalid payload source type")

            with file_handle: # Ensure file/BytesIO gets closed
                while True:
                    self._check_cancel() # Check for cancellation
                    chunk = file_handle.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    bytes_sent += len(chunk)
                    current_time = time.monotonic()
                    elapsed_time = current_time - start_time

                    # Progress update
                    if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_sent == payload_size:
                        speed_bps = bytes_sent / elapsed_time if elapsed_time > 0.01 else 0
                        eta_sec = ((payload_size - bytes_sent) / speed_bps) if speed_bps > 0 else -1
                        self._send_status("progress", "send", bytes_sent, payload_size, speed_bps, eta_sec)
                        last_update_time = current_time

            # Final progress update
            if payload_size > 0:
                elapsed_time = time.monotonic() - start_time
                speed_bps = bytes_sent / elapsed_time if elapsed_time > 0.01 else 0
                self._send_status("progress", "send", bytes_sent, payload_size, speed_bps, 0)

        except FileNotFoundError:
             # This should only happen if is_file was true but file vanished
             raise FileNotFoundError(f"File vanished during send: {payload_source}")
        except InterruptedError: # Propagate cancellation
             raise
        except (socket.error, ssl.SSLError, Exception) as e:
             # Propagate other errors to the main send method
             raise ConnectionAbortedError(f"Error during payload send: {e}") from e

        # Return total bytes sent for verification?
        return bytes_sent


    def send(self):
        """Connects and sends the item (file or text)."""
        raw_sock = None
        sock = None # Can be raw or SSL-wrapped socket
        try:
            # 1. Prepare Header and Payload
            if self.item_type == TRANSFER_TYPE_FILE:
                if not os.path.exists(self.item):
                    raise FileNotFoundError(f"File not found: {self.item}")
                payload_size = os.path.getsize(self.item)
                header_bytes = create_file_header(self.filename, payload_size)
                payload_source = self.item # File path
            elif self.item_type == TRANSFER_TYPE_TEXT:
                payload_bytes = self.item.encode(HEADER_ENCODING)
                payload_size = len(payload_bytes)
                header_bytes = create_text_header(payload_bytes)
                payload_source = payload_bytes # Direct bytes
            else:
                raise ValueError(f"Unsupported item type for sending: {self.item_type}")

            self._send_status("status", f"Connecting to {self.host}:{self.port}...")
            self._check_cancel()

            # 2. Establish Connection
            raw_sock = socket.create_connection((self.host, self.port), timeout=20)
            sock = raw_sock # Start with raw socket

            # 3. Wrap Socket with TLS if enabled
            if self.use_tls:
                 if not self.ssl_context:
                      raise ConnectionAbortedError("TLS enabled but SSL context is missing.")
                 print("Attempting TLS handshake...")
                 self._send_status("status", "Securing connection (TLS)...")
                 try:
                      sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.host) # server_hostname important!
                      print(f"TLS handshake successful. Cipher: {sock.cipher()}")
                 except ssl.SSLError as e:
                      raise ConnectionAbortedError(f"TLS Handshake failed: {e}") from e
                 except Exception as e:
                      raise ConnectionAbortedError(f"Error during TLS wrap: {e}") from e


            self._send_status("status", f"Connected. Sending {self.item_type} '{self.filename}' ({payload_size} bytes)...")
            self._check_cancel()

            # 4. Send Header
            sock.sendall(header_bytes)
            self._check_cancel()

            # --- Optional: Wait for receiver confirmation/rejection ---
            # This requires protocol change (receiver sends ack/reject) - skipping for now

            # 5. Send Payload
            actual_bytes_sent = self._send_payload(sock, payload_source, payload_size)
            self._check_cancel() # Final check after sending

            if actual_bytes_sent != payload_size:
                 raise ConnectionAbortedError(f"Payload size mismatch: expected {payload_size}, sent {actual_bytes_sent}")

            self._send_status("complete", "send", f"{self.item_type} '{self.filename}' sent successfully.")
            print(f"Successfully sent {self.filename} ({actual_bytes_sent}/{payload_size} bytes)")
            return True

        except FileNotFoundError as e:
            self._send_status("error", "send", str(e))
            return False
        except InterruptedError as e:
             self._send_status("error", "send", str(e)) # Report cancellation
             print(f"Send cancelled: {e}")
             return False # Indicate failure due to cancellation
        except (socket.timeout, ConnectionRefusedError) as e:
            self._send_status("error", "send", f"Connection failed: {e}")
            return False
        except (socket.error, ssl.SSLError, ConnectionAbortedError, ConnectionResetError) as e:
            self._send_status("error", "send", f"Network/TLS error: {e}")
            return False
        except Exception as e:
            import traceback
            print(f"Unexpected error in FileSender.send:\n{traceback.format_exc()}")
            self._send_status("error", "send", f"Unexpected error: {e}")
            return False
        finally:
            # Ensure socket is closed
            if sock:
                 try: sock.shutdown(socket.SHUT_RDWR)
                 except (OSError, socket.error): pass
                 sock.close()
            elif raw_sock: # If only raw socket was created (e.g., TLS wrap failed)
                 try: raw_sock.shutdown(socket.SHUT_RDWR)
                 except (OSError, socket.error): pass
                 raw_sock.close()
            print("Sender socket closed.")


# --- File Receiver ---
class FileReceiver(TransferAgent):
    """Listens for connections and handles file/text reception."""
    def __init__(self, config: ConfigManager, status_queue: Queue,
                 stop_event: threading.Event, app_logic_ref): # Need AppLogic ref for confirmation
        super().__init__(status_queue, None) # Receiver doesn't use its own cancel event directly
        self.config = config
        self.stop_event = stop_event # Global server stop event
        self.app_logic = app_logic_ref # Reference to ask for confirmation
        self.server_socket = None
        self._thread = None
        self.active_transfers = {} # Track active connections {addr: cancel_event}
        self.use_tls = self.config.get_boolean_setting('Network', 'enable_tls')
        self.ssl_context = None
        self.cert_dir = Path(self.config.config_path.parent) / CERT_DIR_NAME
        self.cert_file = self.cert_dir / CERT_FILE_NAME
        self.key_file = self.cert_dir / KEY_FILE_NAME

        if self.use_tls:
            self.ssl_context = create_ssl_context(self.cert_dir, self.key_file, self.cert_file, server_side=True)
            if not self.ssl_context:
                 print("TLS is enabled in config, but context creation failed. Disabling TLS.")
                 self.use_tls = False # Fallback to non-TLS


    def _handle_connection(self, raw_client_sock: socket.socket, address: tuple):
        """Handles a single incoming client connection."""
        ip, port = address
        addr_str = f"{ip}:{port}"
        print(f"Incoming connection from {addr_str}")

        sock = raw_client_sock # Start with raw socket
        transfer_cancel_event = threading.Event() # Specific event for this transfer
        self.active_transfers[address] = transfer_cancel_event
        super().__init__(self.status_queue, transfer_cancel_event) # Update base class event

        target_filepath = None
        bytes_received = 0
        header_info = None
        confirmation_result_event = threading.Event() # For confirmation pause/resume
        accepted = False

        try:
            # 1. Optional TLS Handshake
            if self.use_tls:
                 if not self.ssl_context:
                      raise ConnectionAbortedError("TLS enabled but server SSL context is missing.")
                 print(f"Attempting TLS handshake with {addr_str}...")
                 try:
                      sock = self.ssl_context.wrap_socket(raw_client_sock, server_side=True)
                      print(f"TLS handshake successful with {addr_str}. Cipher: {sock.cipher()}")
                 except ssl.SSLError as e:
                      # Handle common handshake errors gracefully
                      if "CERTIFICATE_VERIFY_FAILED" in str(e):
                           print(f"TLS Handshake Warning (client likely using self-signed): {e}")
                           # Decide whether to proceed despite verification failure
                           # For self-signed setups, we might proceed cautiously
                           # sock = self.ssl_context.wrap_socket(raw_client_sock, server_side=True, suppress_ragged_eofs=True) # Example
                           raise ConnectionAbortedError(f"TLS Certificate verification failed: {e}. Adjust trust settings if needed.")

                      else:
                        raise ConnectionAbortedError(f"TLS Handshake failed: {e}") from e
                 except Exception as e:
                      raise ConnectionAbortedError(f"Error during TLS wrap with {addr_str}: {e}") from e

            # 2. Parse Header
            self._check_cancel()
            header_info = parse_header(sock)
            if not header_info:
                raise ValueError(f"Invalid or missing header from {addr_str}.")

            transfer_type = header_info.get('transfer_type')
            metadata = header_info.get('metadata', {})
            data_size = header_info.get('data_size', 0)

            # 3. Handle Transfer Type
            if transfer_type == TRANSFER_TYPE_FILE:
                 filename = metadata.get('filename')
                 source_os = metadata.get('source_os', 'Unknown')
                 if not filename: raise ValueError("Filename missing in FILE header.")

                 # --- Confirmation Step ---
                 if self.config.get_boolean_setting('Preferences', 'confirm_receive'):
                     self._send_status("confirm_receive", filename, data_size, addr_str, confirmation_result_event)
                     # Wait for AppLogic to set the event (with timeout?)
                     print(f"Waiting for user confirmation for '{filename}' from {addr_str}...")
                     confirmed = confirmation_result_event.wait(timeout=300.0) # 5 min timeout
                     if not confirmed or not self.app_logic.get_confirmation_result(addr_str): # Check result stored in AppLogic
                          print(f"Receive rejected by user or timed out for '{filename}'.")
                          try: # Try to inform sender
                               reject_header = create_reject_header("Rejected by user or timeout")
                               sock.sendall(reject_header)
                          except Exception as e: print(f"Could not send rejection notice: {e}")
                          raise InterruptedError("Transfer rejected by user.") # Use InterruptedError
                     print(f"Receive confirmed for '{filename}'.")
                     accepted = True
                 else:
                     accepted = True # Auto-accept if confirmation disabled

                 # --- Proceed with File Reception ---
                 downloads_dir = self.config.get_setting('Preferences', 'downloads_directory')
                 if not Path(downloads_dir).is_dir():
                      print(f"Error: Configured downloads directory invalid: {downloads_dir}. Using fallback.")
                      downloads_dir = get_default_downloads_path() # Use default finder as fallback

                 target_filepath = generate_unique_filepath(downloads_dir, filename)
                 target_filename = os.path.basename(target_filepath)
                 self._send_status("status", f"Receiving '{target_filename}' ({data_size} bytes) from {addr_str}...")
                 print(f"Receiving '{filename}' ({data_size} bytes). Saving to '{target_filepath}'")

                 start_time = time.monotonic()
                 last_update_time = start_time
                 with open(target_filepath, 'wb') as f:
                     while bytes_received < data_size:
                         self._check_cancel() # Check for cancellation during transfer
                         if self.stop_event.is_set(): raise InterruptedError("Server shutdown.")

                         bytes_to_read = min(BUFFER_SIZE, data_size - bytes_received)
                         chunk = sock.recv(bytes_to_read)
                         if not chunk: raise ConnectionAbortedError("Connection closed by sender during file transfer.")
                         f.write(chunk)
                         bytes_received += len(chunk)

                         # Progress update
                         current_time = time.monotonic()
                         elapsed = current_time - start_time
                         if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_received == data_size:
                              speed = bytes_received / elapsed if elapsed > 0.01 else 0
                              eta = (data_size - bytes_received) / speed if speed > 0 else -1
                              self._send_status("progress", "receive", bytes_received, data_size, speed, eta)
                              last_update_time = current_time

                 # Final progress & Verification
                 final_size = os.path.getsize(target_filepath)
                 if final_size != data_size:
                     raise ValueError(f"File size mismatch: Expected {data_size}, Got {final_size}")
                 self._send_status("progress", "receive", bytes_received, data_size, speed, 0)
                 self._send_status("complete", "receive", f"File '{target_filename}' received successfully.")
                 print(f"Successfully received '{target_filename}' ({bytes_received} bytes).")


            elif transfer_type == TRANSFER_TYPE_TEXT:
                 self._send_status("status", f"Receiving text snippet ({data_size} bytes) from {addr_str}...")
                 text_bytes = b''
                 while len(text_bytes) < data_size:
                      self._check_cancel()
                      if self.stop_event.is_set(): raise InterruptedError("Server shutdown.")
                      chunk = sock.recv(min(BUFFER_SIZE, data_size - len(text_bytes)))
                      if not chunk: raise ConnectionAbortedError("Connection closed by sender during text transfer.")
                      text_bytes += chunk

                 received_text = text_bytes.decode(HEADER_ENCODING)
                 print(f"Received text: {received_text[:100]}...") # Log truncated text
                 # Put text on queue for AppLogic to handle (display/copy)
                 self._send_status("text_received", received_text, addr_str)
                 # Send completion status separately
                 self._send_status("complete", "receive", f"Text snippet received successfully from {addr_str}.")


            elif transfer_type == TRANSFER_TYPE_REJECT:
                 # Sender might inform us if *they* reject (less common)
                 reason = metadata.get('reason', 'Unknown reason')
                 print(f"Received REJECT signal from {addr_str}: {reason}")
                 # We don't need to do much here, just log it maybe.
                 self._send_status("info", f"Transfer rejected by {addr_str}: {reason}")

            else:
                 raise ValueError(f"Unsupported transfer type received: {transfer_type}")

        except InterruptedError as e: # Catch cancellation/rejection
             error_msg = f"Transfer cancelled or rejected: {e}"
             print(error_msg)
             # Send cancelled status only if it wasn't a rejection we initiated
             if accepted: # Only send cancel if we initially accepted or didn't need to confirm
                self._send_status("error", "receive", f"Transfer Cancelled: {e}")
             # Clean up partial file if applicable and we accepted
             if accepted and target_filepath and os.path.exists(target_filepath) and bytes_received != data_size:
                  self._cleanup_partial_file(target_filepath)

        except (socket.error, ssl.SSLError, ConnectionAbortedError, ConnectionResetError, ValueError, OSError) as e:
             # Catch specific network, TLS, protocol, or file errors
             error_msg = f"Error during receive from {addr_str}: {e}"
             print(error_msg)
             self._send_status("error", "receive", f"Receive Error: {e}")
             # Clean up partial file
             if target_filepath and os.path.exists(target_filepath) and bytes_received != data_size:
                  self._cleanup_partial_file(target_filepath)
        except Exception as e:
             # Catch any other unexpected errors
             import traceback
             error_msg = f"Unexpected error handling {addr_str}: {e}"
             print(f"{error_msg}\n{traceback.format_exc()}")
             self._send_status("error", "receive", f"Unexpected Receive Error: {e}")
             # Clean up partial file
             if target_filepath and os.path.exists(target_filepath) and bytes_received != data_size:
                  self._cleanup_partial_file(target_filepath)
        finally:
             # Ensure socket is closed and removed from active transfers
             if sock:
                 try: sock.shutdown(socket.SHUT_RDWR)
                 except (OSError, socket.error): pass
                 sock.close()
             elif raw_client_sock: # If only raw socket existed
                 try: raw_client_sock.shutdown(socket.SHUT_RDWR)
                 except (OSError, socket.error): pass
                 raw_client_sock.close()

             if address in self.active_transfers:
                 del self.active_transfers[address]
             print(f"Connection from {addr_str} closed.")


    def _cleanup_partial_file(self, filepath):
        """Attempts to delete a partially downloaded file."""
        try:
            print(f"Attempting to remove incomplete/failed file: {filepath}")
            os.remove(filepath)
            print(f"Removed: {filepath}")
        except OSError as remove_err:
            print(f"Could not remove file '{filepath}': {remove_err}")


    def _run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', APP_PORT))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            protocol = "TLS" if self.use_tls else "TCP"
            print(f"Receiver listening on port {APP_PORT} using {protocol}...")
            self._send_status("status", f"Listening for incoming files ({protocol})")

            while not self.stop_event.is_set():
                try:
                    client_socket, address = self.server_socket.accept()
                    # Don't wrap with TLS here; happens inside _handle_connection if needed
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address),
                        daemon=True
                    )
                    handler_thread.start()
                except socket.timeout:
                    continue # Normal timeout, check stop_event
                except ssl.SSLError as e:
                     # This might catch errors during accept if context is bad, though unlikely
                     print(f"SSL Error during accept (rare): {e}")
                     # Consider stopping if TLS setup is fundamentally broken
                except Exception as e:
                     if not self.stop_event.is_set():
                         print(f"Error accepting connection: {e}")
                         self._send_status("error", "server", f"Server accept error: {e}")
                         time.sleep(0.5)

        except OSError as e:
             error_msg = f"Could not bind receiver to port {APP_PORT}. Error: {e}"
             print(error_msg)
             self._send_status("error","server", error_msg)
        except Exception as e:
             error_msg = f"Unexpected error in receiver server thread: {e}"
             print(f"{error_msg}\n{traceback.format_exc()}")
             if not self.stop_event.is_set():
                 self._send_status("error", "server", error_msg)
        finally:
            print("Receiver server thread shutting down...")
            # Cancel any active transfers managed by this server instance
            active_addrs = list(self.active_transfers.keys()) # Copy keys
            if active_addrs:
                 print(f"Cancelling {len(active_addrs)} active transfer(s)...")
                 for addr in active_addrs:
                     if addr in self.active_transfers:
                          self.active_transfers[addr].set() # Signal cancel
            # Close server socket
            if self.server_socket:
                try: self.server_socket.close()
                except Exception as e: print(f"Error closing server socket: {e}")
            self.server_socket = None
            self._send_status("status", "Receiver stopped.")
            print("Receiver server thread finished.")


    # --- Public Methods ---
    def start(self):
        if not Path(self.config.get_setting('Preferences','downloads_directory')).is_dir():
             print(f"Warning: Invalid downloads directory in config. Receiver may fail.")
             # Correct the config? Or just warn? Let's warn for now.
             # self.config.set_setting('Preferences', 'downloads_directory', get_default_downloads_path())

        if self._thread is None or not self._thread.is_alive():
            print("Starting receiver thread...")
            self._thread = threading.Thread(target=self._run_server, daemon=True)
            self._thread.start()
        else:
             print("Receiver thread already running.")

    def shutdown(self):
        """Signals the receiver thread and active connections to stop."""
        if self._thread and self._thread.is_alive():
            print("Requesting receiver shutdown...")
            # Stop accepting new connections and signal _run_server loop to exit
            self.stop_event.set()
            # Signal existing connection handlers to cancel
            active_addrs = list(self.active_transfers.keys())
            print(f"Signalling cancel for {len(active_addrs)} active transfer(s)...")
            for addr in active_addrs:
                 if addr in self.active_transfers:
                      self.active_transfers[addr].set()
        else:
            print("Receiver shutdown requested, but thread wasn't running.")

    def cancel_transfer(self, address_tuple):
        """Requests cancellation of a specific transfer."""
        if address_tuple in self.active_transfers:
            print(f"Requesting cancellation for transfer from {address_tuple}")
            self.active_transfers[address_tuple].set()
            return True
        else:
             print(f"No active transfer found for address {address_tuple} to cancel.")
             return False