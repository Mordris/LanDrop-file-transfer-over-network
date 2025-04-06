import socket
import threading
import os
import time
import ssl
from queue import Queue, Empty
from pathlib import Path
import traceback # For detailed error logging
from io import BytesIO # For sending text payload

# Relative imports
from .protocol import (create_file_header, create_text_header, create_reject_header,
                      create_accept_header, parse_header, HEADER_ENCODING)
from ..utils.file_utils import generate_unique_filepath, ensure_certificates
from ..utils.config_manager import ConfigManager
from ..utils.constants import (APP_PORT, TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                        TRANSFER_TYPE_ACCEPT, TRANSFER_TYPE_REJECT,
                        CERT_DIR_NAME, CERT_FILE_NAME, KEY_FILE_NAME)


BUFFER_SIZE = 4096 * 16 # 64KB buffer
PROGRESS_UPDATE_INTERVAL = 0.25 # seconds
ACCEPTANCE_TIMEOUT = 45.0 # seconds to wait for ACCEPT/REJECT
CONNECTION_TIMEOUT = 20.0 # seconds for initial connection
HANDSHAKE_TIMEOUT = 15.0 # seconds for TLS handshake
DATA_TIMEOUT = 60.0 # seconds timeout for individual data chunk recv/send

# --- TLS Context Setup ---
def create_ssl_context(cert_dir: Path, key_file: Path, cert_file: Path, server_side: bool = False) -> ssl.SSLContext | None:
    """Creates SSL context for server or client."""
    if not ensure_certificates(cert_dir, key_file, cert_file):
        print("Cannot proceed without TLS certificates.")
        return None
    try:
        # Use secure defaults if possible (requires newer Python/OpenSSL)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if not server_side else ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2 # Require TLS 1.2 or higher
            # Recommended secure cipher suite selection (adjust if compatibility needed)
            # context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
        except AttributeError: # Fallback for older Python versions
             print("Warning: Using default TLS settings (TLSv1.2+ not available/enforced).")
             context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) # Allows negotiation

        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        if not server_side:
            # Client: Configure verification (IMPORTANT FOR PRODUCTION)
            # For self-signed testing:
            context.check_hostname = False # Disable hostname check only for self-signed
            context.verify_mode = ssl.CERT_NONE # Do NOT verify chain for self-signed testing
            print("TLS Client: WARNING - Server certificate verification is DISABLED (for self-signed certs).")
            # For production with proper CAs:
            # context.check_hostname = True
            # context.verify_mode = ssl.CERT_REQUIRED
            # context.load_default_certs() # Or load_verify_locations(cafile='path/to/ca-bundle.crt')
        else:
            # Server: Doesn't need to verify client by default
             print("TLS Server: Context created.")
             # If client certs needed: context.verify_mode = ssl.CERT_REQUIRED; context.load_verify_locations(...)

        return context
    except ssl.SSLError as e: print(f"SSL Error creating context: {e}")
    except FileNotFoundError: print(f"Certificate or Key file not found ({cert_file}, {key_file})")
    except Exception as e: print(f"Unexpected error creating SSL context: {e}")
    return None

# --- Base Class ---
class TransferAgent:
    """Base class for Sender/Receiver with common methods."""
    def __init__(self, status_queue: Queue, cancel_event: threading.Event | None): # Allow None
        self.status_queue = status_queue
        self.cancel_event = cancel_event

    def _send_status(self, *args):
        if self.status_queue:
            try: self.status_queue.put(args)
            except Exception as e: print(f"Error sending status to queue: {e}")

    def _check_cancel(self):
        """Checks if cancellation has been requested."""
        if self.cancel_event and self.cancel_event.is_set():
            raise InterruptedError("Transfer cancelled by user.")

# --- File Sender ---
class FileSender(TransferAgent):
    """Handles sending a single file or text snippet to a peer."""
    def __init__(self, host: str, port: int, item: str, item_type: str,
                 status_queue: Queue, cancel_event: threading.Event,
                 use_tls: bool, ssl_context: ssl.SSLContext | None):
        super().__init__(status_queue, cancel_event)
        self.host = host
        self.port = port
        self.item = item # Filepath or text content
        self.item_type = item_type # TRANSFER_TYPE_FILE or TRANSFER_TYPE_TEXT
        self.use_tls = use_tls
        self.ssl_context = ssl_context
        self.filename = os.path.basename(item) if item_type == TRANSFER_TYPE_FILE and isinstance(item, str) else "text_snippet.txt"

    def _send_payload(self, sock: socket.socket, payload_source, payload_size: int):
        """Sends either file or text payload with progress."""
        bytes_sent = 0
        start_time = time.monotonic()
        last_update_time = start_time
        file_handle = None
        try:
            is_file = isinstance(payload_source, str) and os.path.exists(payload_source)
            if is_file:
                file_handle = open(payload_source, 'rb')
            elif isinstance(payload_source, bytes):
                 file_handle = BytesIO(payload_source)
            else:
                 raise TypeError("Invalid payload source type")

            while True:
                self._check_cancel()
                chunk = file_handle.read(BUFFER_SIZE)
                if not chunk: break # End of source

                # Send chunk with data timeout
                sock.settimeout(DATA_TIMEOUT)
                sock.sendall(chunk)
                sock.settimeout(None) # Reset timeout after send if needed, or keep DATA_TIMEOUT?

                bytes_sent += len(chunk)
                current_time = time.monotonic()
                elapsed_time = max(0.01, current_time - start_time) # Avoid division by zero

                # Progress update
                if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_sent == payload_size:
                    speed_bps = bytes_sent / elapsed_time
                    eta_sec = ((payload_size - bytes_sent) / speed_bps) if speed_bps > 0 else -1
                    self._send_status("progress", "send", bytes_sent, payload_size, speed_bps, eta_sec)
                    last_update_time = current_time

            # Final progress update
            if payload_size >= 0: # Check size >= 0 to handle 0-byte case
                elapsed_time = max(0.01, time.monotonic() - start_time)
                speed_bps = bytes_sent / elapsed_time
                self._send_status("progress", "send", bytes_sent, payload_size, speed_bps, 0) # ETA is 0

        except FileNotFoundError: raise FileNotFoundError(f"File vanished during send: {payload_source}")
        except InterruptedError: raise # Propagate cancellation
        except (socket.error, ssl.SSLError, OSError) as e: raise ConnectionAbortedError(f"Error during payload send: {e}") from e
        finally:
             if file_handle: file_handle.close() # Ensure source is closed

        return bytes_sent

    def send(self):
        """Connects, sends header, waits for acceptance, then sends item."""
        raw_sock = None; sock = None; payload_size = -1
        try:
            # 1. Prepare Header and Payload Source
            if self.item_type == TRANSFER_TYPE_FILE:
                if not isinstance(self.item, str) or not os.path.exists(self.item): raise FileNotFoundError(f"File not found: {self.item}")
                payload_size = os.path.getsize(self.item)
                header_bytes = create_file_header(self.filename, payload_size)
                payload_source = self.item # File path
            elif self.item_type == TRANSFER_TYPE_TEXT:
                if not isinstance(self.item, str): raise TypeError("Text item must be a string")
                payload_bytes = self.item.encode(HEADER_ENCODING)
                payload_size = len(payload_bytes)
                header_bytes = create_text_header(payload_bytes)
                payload_source = payload_bytes # Direct bytes
            else: raise ValueError(f"Unsupported item type for sending: {self.item_type}")

            self._send_status("status", f"Connecting to {self.host}:{self.port}...")
            self._check_cancel()

            # 2. Establish Connection & Optional TLS
            raw_sock = socket.create_connection((self.host, self.port), timeout=CONNECTION_TIMEOUT)
            sock = raw_sock
            if self.use_tls:
                 if not self.ssl_context: raise ConnectionAbortedError("TLS enabled but SSL context is missing.")
                 self._send_status("status", "Securing connection (TLS)...")
                 try:
                      sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.host,
                                                          do_handshake_on_connect=True, suppress_ragged_eofs=True)
                      # Set timeout for handshake (wrap_socket might block)
                      # Note: Setting timeout *before* wrap_socket is generally better if possible
                      # sock.settimeout(HANDSHAKE_TIMEOUT) # Timeout applies to handshake operations
                      print(f"TLS handshake successful. Cipher: {sock.cipher()}")
                 except ssl.SSLError as e: raise ConnectionAbortedError(f"TLS Handshake failed: {e}") from e
                 except socket.timeout: raise ConnectionAbortedError("TLS Handshake timed out.") from None
                 except Exception as e: raise ConnectionAbortedError(f"Error during TLS wrap: {e}") from e
                 finally: sock.settimeout(None) # Reset timeout after handshake if needed

            self._send_status("status", f"Connected. Sending request ({self.item_type} '{self.filename}')...")
            self._check_cancel()

            # 3. Send Header
            sock.settimeout(DATA_TIMEOUT) # Timeout for sending header
            sock.sendall(header_bytes)
            sock.settimeout(None)
            self._check_cancel()

            # 4. Wait for Acceptance (Only for file transfers, text assumed accepted)
            if self.item_type == TRANSFER_TYPE_FILE:
                self._send_status("status", "Waiting for receiver acceptance...")
                print(f"Sender: Waiting for ACCEPT/REJECT (timeout={ACCEPTANCE_TIMEOUT}s)...")
                response_header = parse_header(sock, timeout=ACCEPTANCE_TIMEOUT)

                if response_header is None: raise ConnectionAbortedError("No valid response from receiver (Timeout/Closed).")

                response_type = response_header.get('transfer_type')
                if response_type == TRANSFER_TYPE_ACCEPT:
                     print("Sender: Received ACCEPT signal.")
                     self._send_status("status", f"Receiver accepted. Sending '{self.filename}'...")
                     # Proceed to send payload
                elif response_type == TRANSFER_TYPE_REJECT:
                     reason = response_header.get('metadata', {}).get('reason', 'No reason given')
                     print(f"Sender: Received REJECT signal. Reason: {reason}")
                     raise InterruptedError(f"Transfer rejected by receiver: {reason}")
                else: raise ConnectionAbortedError(f"Unexpected response type from receiver: {response_type}")
            else:
                # For TEXT, assume implicit acceptance after header sent successfully
                self._send_status("status", f"Sending text snippet...")

            # 5. Send Payload
            self._check_cancel()
            actual_bytes_sent = self._send_payload(sock, payload_source, payload_size)
            self._check_cancel()

            if actual_bytes_sent != payload_size: raise ConnectionAbortedError(f"Payload size mismatch: expected {payload_size}, sent {actual_bytes_sent}")

            self._send_status("complete", "send", f"{self.item_type} '{self.filename}' sent successfully.")
            print(f"Successfully sent {self.filename} ({actual_bytes_sent}/{payload_size} bytes)")
            return True

        # --- Error Handling ---
        except FileNotFoundError as e: self._send_status("error", "send", str(e)); return False
        except InterruptedError as e: self._send_status("error", "cancel", str(e)); print(f"Send cancelled/rejected: {e}"); return False # Report as 'cancel' type
        except (socket.timeout, ConnectionRefusedError) as e: self._send_status("error", "send", f"Connection failed: {e}"); return False
        except (socket.error, ssl.SSLError, ConnectionAbortedError, ConnectionResetError, OSError) as e:
            error_msg = f"Network/TLS error: {e}"
            if "response received" in str(e) or "timed out" in str(e).lower(): error_msg = f"Receiver response error: {e}"
            self._send_status("error", "send", error_msg); return False
        except Exception as e: print(f"Unexpected error in FileSender.send:\n{traceback.format_exc()}"); self._send_status("error", "send", f"Unexpected send error: {e}"); return False
        finally:
             # Graceful socket closure
             if sock:
                 try:
                     sock.shutdown(socket.SHUT_RDWR)
                 except Exception:
                     pass
                 try:
                     sock.close()
                 except Exception:
                     pass
             elif raw_sock:
                 try:
                     raw_sock.shutdown(socket.SHUT_RDWR)
                 except Exception:
                     pass
                 try:
                     raw_sock.close()
                 except Exception:
                     pass
             print("Sender socket closed.")


# --- File Receiver ---
class FileReceiver(TransferAgent):
    """Listens for connections and handles file/text reception."""
    def __init__(self, config: ConfigManager, status_queue: Queue,
                 stop_event: threading.Event, app_logic_ref):
        super().__init__(status_queue, None) # Base event not used by server loop
        self.config = config; self.stop_event = stop_event; self.app_logic = app_logic_ref
        self.server_socket = None; self._thread = None
        self.active_transfers = {} # {addr_tuple: cancel_event}
        self.use_tls = self.config.get_boolean_setting('Network', 'enable_tls')
        self.ssl_context = None; self.cert_dir = Path(self.config.config_path.parent) / CERT_DIR_NAME
        self.cert_file = self.cert_dir / CERT_FILE_NAME; self.key_file = self.cert_dir / KEY_FILE_NAME
        if self.use_tls:
            self.ssl_context = create_ssl_context(self.cert_dir, self.key_file, self.cert_file, server_side=True)
            if not self.ssl_context: print("TLS enabled, but context failed. Disabling TLS for receiving."); self.use_tls = False

    def _handle_connection(self, raw_client_sock: socket.socket, address: tuple):
        ip, port = address; addr_str = f"{ip}:{port}"
        print(f"Incoming connection from {addr_str}")
        sock = raw_client_sock; transfer_cancel_event = threading.Event()
        self.active_transfers[address] = transfer_cancel_event
        # Re-init base agent with the specific cancel event for this transfer
        super().__init__(self.status_queue, transfer_cancel_event)

        target_filepath = None; bytes_received = 0; header_info = None; accepted = False

        try:
            # 1. Optional TLS Handshake
            if self.use_tls:
                 if not self.ssl_context: raise ConnectionAbortedError("TLS enabled but server SSL context missing.")
                 print(f"Attempting TLS handshake with {addr_str}...")
                 try:
                      # Use a timeout for the handshake itself
                      raw_client_sock.settimeout(HANDSHAKE_TIMEOUT)
                      sock = self.ssl_context.wrap_socket(raw_client_sock, server_side=True,
                                                          do_handshake_on_connect=True, suppress_ragged_eofs=True)
                      sock.settimeout(None) # Reset timeout after handshake
                      print(f"TLS handshake successful with {addr_str}. Cipher: {sock.cipher()}")
                 except ssl.SSLError as e: sock.settimeout(None); raise ConnectionAbortedError(f"TLS Handshake failed: {e}") from e
                 except socket.timeout: sock.settimeout(None); raise ConnectionAbortedError("TLS Handshake timed out.") from None
                 except Exception as e: sock.settimeout(None); raise ConnectionAbortedError(f"Error during TLS wrap with {addr_str}: {e}") from e

            # 2. Parse Initial Header
            self._check_cancel()
            header_info = parse_header(sock, timeout=30.0) # Generous timeout for first header
            if not header_info: raise ValueError(f"Invalid or missing header from {addr_str}.")

            transfer_type = header_info.get('transfer_type')
            metadata = header_info.get('metadata', {})
            data_size = header_info.get('data_size', 0)

            # 3. Handle Transfer Type and Acceptance/Rejection
            if transfer_type == TRANSFER_TYPE_FILE:
                 filename = metadata.get('filename')
                 if not filename: raise ValueError("Filename missing in FILE header.")

                 # --- Confirmation Step ---
                 confirmation_result_event = threading.Event()
                 user_confirmed = False
                 if self.config.get_boolean_setting('Preferences', 'confirm_receive'):
                     self._send_status("confirm_receive", filename, data_size, addr_str, confirmation_result_event)
                     print(f"Waiting for user confirmation for '{filename}' from {addr_str}...")
                     confirmed_in_time = confirmation_result_event.wait(timeout=300.0) # 5 min timeout
                     if not confirmed_in_time or not self.app_logic.get_confirmation_result(addr_str):
                          reason = "Rejected by user" if confirmed_in_time else "Confirmation timeout"
                          print(f"Receive {reason.lower()} for '{filename}'.")
                          try: sock.sendall(create_reject_header(reason))
                          except Exception as send_e: print(f"Error sending REJECT: {send_e}")
                          raise InterruptedError(reason)
                     else: user_confirmed = True
                 else: user_confirmed = True # Auto-accept

                 # --- Send ACCEPT signal ---
                 print(f"Receiver: Sending ACCEPT signal for '{filename}' to {addr_str}")
                 sock.sendall(create_accept_header())
                 accepted = True

                 # --- Proceed with File Reception ---
                 downloads_dir = self.config.get_setting('Preferences', 'downloads_directory')
                 # ... (downloads dir validation/fallback remains same) ...
                 if not Path(downloads_dir).is_dir(): fallback_path = self.config._defaults['Preferences']['downloads_directory']; print(f"Error: Invalid downloads dir: {downloads_dir}. Using fallback: {fallback_path}"); downloads_dir = fallback_path

                 target_filepath = generate_unique_filepath(downloads_dir, filename)
                 target_filename = os.path.basename(target_filepath)
                 self._send_status("status", f"Receiving '{target_filename}' ({data_size} bytes)...")
                 print(f"Receiving '{filename}' ({data_size} bytes). Saving to '{target_filepath}'")

                 start_time = time.monotonic()
                 last_update_time = start_time
                 with open(target_filepath, 'wb') as f:
                     while bytes_received < data_size:
                         self._check_cancel()
                         if self.stop_event.is_set(): raise InterruptedError("Server shutdown.")
                         bytes_to_read = min(BUFFER_SIZE, data_size - bytes_received)
                         sock.settimeout(DATA_TIMEOUT) # Timeout for receiving data chunk
                         chunk = sock.recv(bytes_to_read)
                         sock.settimeout(None) # Reset timeout
                         if not chunk: raise ConnectionAbortedError("Connection closed by sender during file transfer.")
                         f.write(chunk)
                         bytes_received += len(chunk)
                         # ... (progress update logic remains same) ...
                         current_time = time.monotonic(); elapsed = max(0.01, current_time - start_time)
                         if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_received == data_size:
                              speed = bytes_received / elapsed; eta = (data_size - bytes_received) / speed if speed > 0 else -1
                              self._send_status("progress", "receive", bytes_received, data_size, speed, eta); last_update_time = current_time

                 # Final progress & Verification
                 final_size = os.path.getsize(target_filepath)
                 if final_size != data_size: raise ValueError(f"File size mismatch: Expected {data_size}, Got {final_size}")
                 if data_size >= 0: # Send final progress update
                     elapsed = max(0.01, time.monotonic() - start_time); speed = bytes_received / elapsed
                     self._send_status("progress", "receive", bytes_received, data_size, speed, 0)
                 self._send_status("complete", "receive", f"File '{target_filename}' received successfully.")
                 print(f"Successfully received '{target_filename}' ({bytes_received} bytes).")

            elif transfer_type == TRANSFER_TYPE_TEXT:
                 # Implicit acceptance for text
                 accepted = True # Mark as accepted for cleanup logic if needed
                 self._send_status("status", f"Receiving text snippet ({data_size} bytes)...")
                 text_bytes = b''
                 # Use data timeout for text reception as well
                 sock.settimeout(DATA_TIMEOUT)
                 while len(text_bytes) < data_size:
                      self._check_cancel()
                      if self.stop_event.is_set(): raise InterruptedError("Server shutdown.")
                      chunk = sock.recv(min(BUFFER_SIZE, data_size - len(text_bytes)))
                      if not chunk: raise ConnectionAbortedError("Connection closed by sender during text transfer.")
                      text_bytes += chunk
                 sock.settimeout(None) # Reset timeout

                 received_text = text_bytes.decode(HEADER_ENCODING)
                 print(f"Received text: {received_text[:100]}...")
                 self._send_status("text_received", received_text, addr_str)
                 self._send_status("complete", "receive", f"Text snippet received successfully from {addr_str}.")

            else:
                 # Reject unknown types
                 print(f"Rejecting unknown transfer type: {transfer_type}")
                 try: sock.sendall(create_reject_header(f"Unsupported type: {transfer_type}"))
                 except Exception as send_e: print(f"Error sending REJECT for unknown type: {send_e}")
                 raise ValueError(f"Unsupported transfer type received: {transfer_type}")

        except InterruptedError as e: # Catch cancellation/rejection
             error_msg = f"Transfer cancelled or rejected: {e}"; print(error_msg)
             if accepted: self._send_status("error", "cancel", f"Transfer Cancelled: {e}") # Send cancel status only if we accepted
             if accepted and target_filepath and os.path.exists(target_filepath) and bytes_received != data_size: self._cleanup_partial_file(target_filepath)
        except (socket.error, ssl.SSLError, ConnectionAbortedError, ConnectionResetError, ValueError, OSError) as e:
             error_msg = f"Error during receive from {addr_str}: {e}"; print(error_msg)
             self._send_status("error", "receive", f"Receive Error: {e}")
             if accepted and target_filepath and os.path.exists(target_filepath) and bytes_received != data_size: self._cleanup_partial_file(target_filepath)
        except Exception as e:
             error_msg = f"Unexpected error handling {addr_str}: {e}"; print(f"{error_msg}\n{traceback.format_exc()}")
             self._send_status("error", "receive", f"Unexpected Receive Error: {e}")
             if accepted and target_filepath and os.path.exists(target_filepath) and bytes_received != data_size: self._cleanup_partial_file(target_filepath)
        finally:
             # Graceful socket closure and cleanup
             if sock:
                 try:
                     sock.shutdown(socket.SHUT_RDWR)
                 except Exception:
                     pass
                 try:
                     sock.close()
                 except Exception:
                     pass
             elif raw_client_sock:
                 try:
                     raw_client_sock.shutdown(socket.SHUT_RDWR)
                 except Exception:
                     pass
                 try:
                     raw_client_sock.close()
                 except Exception:
                     pass
             if address in self.active_transfers: del self.active_transfers[address]
             if addr_str in self.confirmation_results: del self.confirmation_results[addr_str] # Clean up confirmation results too
             print(f"Connection from {addr_str} closed.")

    def _cleanup_partial_file(self, filepath): # ... (remains the same) ...
        try: print(f"Attempting to remove incomplete/failed file: {filepath}"); os.remove(filepath); print(f"Removed: {filepath}")
        except OSError as remove_err: print(f"Could not remove file '{filepath}': {remove_err}")

    def _run_server(self): # ... (remains the same) ...
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', APP_PORT)); self.server_socket.listen(5); self.server_socket.settimeout(1.0)
            protocol = "TLS" if self.use_tls else "TCP"; print(f"Receiver listening on port {APP_PORT} using {protocol}..."); self._send_status("status", f"Listening ({protocol})")
            while not self.stop_event.is_set():
                try: client_socket, address = self.server_socket.accept(); handler_thread = threading.Thread(target=self._handle_connection, args=(client_socket, address), daemon=True); handler_thread.start()
                except socket.timeout: continue
                except ssl.SSLError as e: print(f"SSL Error during accept: {e}") # Log SSL errors during accept
                except Exception as e:
                     if not self.stop_event.is_set(): print(f"Error accepting connection: {e}"); self._send_status("error", "server", f"Server accept error: {e}"); time.sleep(0.5)
        except OSError as e: error_msg = f"Could not bind receiver to port {APP_PORT}: {e}"; print(error_msg); self._send_status("error","server", error_msg)
        except Exception as e: error_msg = f"Unexpected error in receiver server thread: {e}"; print(f"{error_msg}\n{traceback.format_exc()}");
        finally: print("Receiver server thread shutting down..."); active_addrs = list(self.active_transfers.keys());
        if active_addrs: print(f"Cancelling {len(active_addrs)} active transfer(s)..."); [self.active_transfers[addr].set() for addr in active_addrs if addr in self.active_transfers]
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"Error closing server socket: {e}")
        self.server_socket = None; self._send_status("status", "Receiver stopped."); print("Receiver server thread finished.")


    def start(self): # ... (remains the same) ...
        if not Path(self.config.get_setting('Preferences','downloads_directory')).is_dir(): print(f"Warning: Invalid downloads directory in config.")
        if self._thread is None or not self._thread.is_alive(): print("Starting receiver thread..."); self._thread = threading.Thread(target=self._run_server, daemon=True); self._thread.start()
        else: print("Receiver thread already running.")

    def shutdown(self): # ... (remains the same) ...
        if self._thread and self._thread.is_alive(): print("Requesting receiver shutdown..."); self.stop_event.set(); active_addrs = list(self.active_transfers.keys()); print(f"Signalling cancel for {len(active_addrs)} active transfer(s)..."); [self.active_transfers[addr].set() for addr in active_addrs if addr in self.active_transfers]
        else: print("Receiver shutdown requested, but thread wasn't running.")

    def cancel_transfer(self, address_tuple): # ... (remains the same) ...
        if address_tuple in self.active_transfers: print(f"Requesting cancellation for transfer from {address_tuple}"); self.active_transfers[address_tuple].set(); return True
        else: print(f"No active transfer found for address {address_tuple} to cancel."); return False