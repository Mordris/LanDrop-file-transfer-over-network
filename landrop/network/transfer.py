import socket
import threading
import os
import time
import ssl
from queue import Queue, Empty
from pathlib import Path
import traceback
from io import BytesIO
import shutil # For removing directories in cleanup

# --- Relative Imports ---
# Corrected: Import ACK_BYTE from constants, not protocol
from .protocol import (create_file_header, create_text_header,
                      create_multi_start_header, create_multi_file_header, create_multi_end_header,
                      create_reject_header, create_accept_header,
                      parse_header, HEADER_ENCODING) # Removed ACK_BYTE from here
from ..utils.file_utils import generate_unique_filepath, ensure_certificates
from ..utils.config_manager import ConfigManager
from ..utils.constants import (APP_PORT,
                        TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                        TRANSFER_TYPE_MULTI_START, TRANSFER_TYPE_MULTI_FILE, TRANSFER_TYPE_MULTI_END,
                        TRANSFER_TYPE_ACCEPT, TRANSFER_TYPE_REJECT,
                        CERT_DIR_NAME, CERT_FILE_NAME, KEY_FILE_NAME,
                        ACK_BYTE) # *** ACK_BYTE imported correctly from constants ***


# --- Constants --- (Defined in constants.py, but kept here for context)
BUFFER_SIZE = 4096 * 16 # 64KB buffer
PROGRESS_UPDATE_INTERVAL = 0.25 # seconds
ACCEPTANCE_TIMEOUT = 45.0 # Wait for ACCEPT/REJECT
CONNECTION_TIMEOUT = 20.0 # Initial connection
HANDSHAKE_TIMEOUT = 15.0 # TLS handshake
DATA_TIMEOUT = 60.0 # Individual data chunk recv/send, also used for ACK timeout
HEADER_TIMEOUT = 30.0 # Timeout for reading headers


# --- TLS Context Setup ---
def create_ssl_context(cert_dir: Path, key_file: Path, cert_file: Path, server_side: bool = False) -> ssl.SSLContext | None:
    """Creates an SSL context for client or server use."""
    if not ensure_certificates(cert_dir, key_file, cert_file): return None
    try:
        try: # Use secure defaults if possible
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if not server_side else ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Recommended secure cipher suite selection (adjust if compatibility needed)
            # context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
        except AttributeError: # Fallback for older Python versions
             print("Warning: Using default TLS settings (TLSv1.2+ not enforced).")
             context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) # Allows negotiation

        # Load certificate chain and private key
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        if not server_side: # Client-side configuration
            # For self-signed testing ONLY: Disable hostname check and certificate verification.
            # !!! THIS IS INSECURE FOR PRODUCTION !!!
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            print("TLS Client: WARNING - Server certificate verification is DISABLED (for self-signed certs).")
            # For production with proper CAs:
            # context.check_hostname = True
            # context.verify_mode = ssl.CERT_REQUIRED
            # context.load_default_certs() # Or load_verify_locations(cafile='path/to/ca-bundle.crt')
        else: # Server-side configuration
             print("TLS Server: Context created.")
             # If client certificate authentication is needed (mTLS):
             # context.verify_mode = ssl.CERT_REQUIRED
             # context.load_verify_locations(cafile='path/to/client_ca_bundle.crt')

        return context
    except ssl.SSLError as e: print(f"SSL Error creating context: {e}")
    except FileNotFoundError: print(f"Certificate or Key file not found ({cert_file}, {key_file})")
    except Exception as e: print(f"Unexpected error creating SSL context: {e}")
    return None


# --- Base Class ---
class TransferAgent:
    """Base class for Sender/Receiver with common status and cancellation checks."""
    def __init__(self, status_queue: Queue, cancel_event: threading.Event | None):
        self.status_queue = status_queue
        self.cancel_event = cancel_event

    def _send_status(self, *args):
        """Puts a status message onto the shared queue."""
        if self.status_queue:
            try: self.status_queue.put(args)
            except Exception as e: print(f"Error sending status to queue: {e}")

    def _check_cancel(self):
        """Checks if cancellation has been requested via the event."""
        if self.cancel_event and self.cancel_event.is_set():
            raise InterruptedError("Transfer cancelled by user.")

# --- File Sender ---
class FileSender(TransferAgent):
    """Handles sending single files, text snippets, or multiple files/folders."""
    def __init__(self, host: str, port: int,
                 status_queue: Queue, cancel_event: threading.Event,
                 use_tls: bool, ssl_context: ssl.SSLContext | None,
                 item_type: str, # FILE, TEXT, or MULTI_START
                 # Provide EITHER item OR multi-transfer details:
                 item: str | None = None,             # File path or text content for single item
                 file_list: list | None = None,       # List of (abs_path, rel_path) for multi
                 total_items: int = 0,                # For multi
                 total_size: int = 0,                 # For multi
                 base_name: str = "transfer"          # For multi (folder name etc)
                 ):
        super().__init__(status_queue, cancel_event)
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.ssl_context = ssl_context
        self.item_type = item_type
        self.item = item
        self.file_list = file_list if file_list else []
        self.total_items = total_items
        self.total_size = total_size
        self.base_name = base_name

        # Determine display name for logging/status
        self.display_name = "Unknown Item"
        if item_type == TRANSFER_TYPE_FILE and item: self.display_name = os.path.basename(item)
        elif item_type == TRANSFER_TYPE_TEXT: self.display_name = "Text Snippet"
        elif item_type == TRANSFER_TYPE_MULTI_START: self.display_name = base_name


    def _send_payload(self, sock: socket.socket, payload_source, payload_size: int, context_msg: str = ""):
        """Sends file or text payload chunk by chunk with progress updates."""
        bytes_sent = 0
        start_time = time.monotonic()
        last_update_time = start_time
        file_handle = None
        try:
            is_file = isinstance(payload_source, (str, Path)) and os.path.exists(payload_source)
            if is_file:
                file_handle = open(payload_source, 'rb')
            elif isinstance(payload_source, bytes):
                 file_handle = BytesIO(payload_source) # Use BytesIO for bytes payload
            else:
                 raise TypeError(f"Invalid payload source type: {type(payload_source)}")

            while True:
                self._check_cancel() # Check cancellation before reading/sending chunk
                chunk = file_handle.read(BUFFER_SIZE)
                if not chunk: break # End of data

                sock.settimeout(DATA_TIMEOUT)
                sock.sendall(chunk) # sendall ensures all data in chunk is sent
                sock.settimeout(None)

                bytes_sent += len(chunk)
                current_time = time.monotonic()
                elapsed_time = max(0.01, current_time - start_time)

                # Send progress update periodically or on completion
                if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_sent == payload_size:
                    speed_bps = bytes_sent / elapsed_time
                    eta_sec = ((payload_size - bytes_sent) / speed_bps) if speed_bps > 0 else 0
                    self._send_status("progress", "send", bytes_sent, payload_size, speed_bps, eta_sec, context_msg)
                    last_update_time = current_time

            # Send final progress update for this specific payload
            if payload_size >= 0:
                elapsed_time = max(0.01, time.monotonic() - start_time)
                speed_bps = bytes_sent / elapsed_time if elapsed_time > 0 else 0
                self._send_status("progress", "send", bytes_sent, payload_size, speed_bps, 0, context_msg)

        except FileNotFoundError: raise FileNotFoundError(f"File vanished during send: {payload_source}")
        except InterruptedError: raise
        except (socket.error, ssl.SSLError, OSError) as e:
             raise ConnectionAbortedError(f"Error sending payload '{context_msg}': {e}") from e
        finally:
             if file_handle: file_handle.close() # Ensure file handle is closed

        return bytes_sent

    def send(self):
        """Main entry point for sending. Connects and calls appropriate send method."""
        raw_sock = None; sock = None; success = False
        try:
            self._send_status("status", f"Connecting to {self.host}:{self.port}...")
            self._check_cancel()

            # 1. Establish Connection & Optional TLS Handshake
            raw_sock = socket.create_connection((self.host, self.port), timeout=CONNECTION_TIMEOUT)
            sock = raw_sock
            if self.use_tls:
                 if not self.ssl_context: raise ConnectionAbortedError("TLS enabled but SSL context missing.")
                 self._send_status("status", "Securing connection (TLS)...")
                 try:
                      sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.host, do_handshake_on_connect=False)
                      sock.settimeout(HANDSHAKE_TIMEOUT); sock.do_handshake(); sock.settimeout(None)
                      print(f"TLS handshake successful. Cipher: {sock.cipher()}")
                 except ssl.SSLError as e: sock.settimeout(None); raise ConnectionAbortedError(f"TLS Handshake failed: {e}") from e
                 except socket.timeout: sock.settimeout(None); raise ConnectionAbortedError("TLS Handshake timed out.") from None
                 except Exception as e: sock.settimeout(None); raise ConnectionAbortedError(f"Error during TLS wrap/handshake: {e}") from e

            self._send_status("status", f"Connected. Sending request ({self.item_type} '{self.display_name}')...")
            self._check_cancel()

            # 2. Delegate to Specific Send Method
            if self.item_type == TRANSFER_TYPE_FILE: success = self._send_single_file(sock)
            elif self.item_type == TRANSFER_TYPE_TEXT: success = self._send_text(sock)
            elif self.item_type == TRANSFER_TYPE_MULTI_START: success = self._send_multi(sock)
            else: raise ValueError(f"Internal Error: Unsupported item type: {self.item_type}")

            # 3. Report Final Status Based on Success Flag
            if success:
                completion_msg = f"'{self.display_name}' sent successfully."
                if self.item_type == TRANSFER_TYPE_MULTI_START:
                    completion_msg = f"Batch '{self.base_name}' ({self.total_items} items) sent successfully."
                self._send_status("complete", "send", completion_msg)
                print(f"Send completed successfully for: {self.display_name}")
                return True
            else:
                # Specific error should have been reported via _send_status("error", ...)
                print(f"Send failed or was incomplete for: {self.display_name}")
                return False

        # --- Centralized Error Handling for send() method ---
        except InterruptedError as e: self._send_status("error", "cancel", str(e)); print(f"Send cancelled/rejected: {e}"); return False
        except (socket.timeout, ConnectionRefusedError, OSError) as e: err_msg = f"Connection failed: {e}"; self._send_status("error", "send", err_msg); print(err_msg); return False
        except (socket.error, ssl.SSLError, ConnectionAbortedError, ConnectionResetError) as e: error_msg = f"Network/TLS error: {e}"; self._send_status("error", "send", error_msg); print(error_msg); return False
        except Exception as e: print(f"Unexpected error in send():\n{traceback.format_exc()}"); self._send_status("error", "send", f"Unexpected send error: {e}"); return False
        finally:
             # Graceful Socket Closure
             if sock:
                 try: sock.shutdown(socket.SHUT_RDWR)
                 except Exception: pass
                 try: sock.close()
                 except Exception: pass
             elif raw_sock: # Ensure raw socket is closed if TLS failed
                 try: raw_sock.shutdown(socket.SHUT_RDWR)
                 except Exception: pass
                 try: raw_sock.close()
                 except Exception: pass
             print(f"Sender socket closed for {self.host}:{self.port}.")


    def _send_single_file(self, sock: socket.socket) -> bool:
        """Handles the protocol flow for sending a single file."""
        if not self.item or not isinstance(self.item, str) or not os.path.exists(self.item):
            raise FileNotFoundError(f"File not found or invalid: {self.item}")
        payload_size = os.path.getsize(self.item); filename = os.path.basename(self.item)
        header_bytes = create_file_header(filename, payload_size)

        # 1. Send Header
        sock.settimeout(HEADER_TIMEOUT); sock.sendall(header_bytes); sock.settimeout(None)
        self._check_cancel()

        # 2. Wait for Acceptance
        self._send_status("status", "Waiting for receiver acceptance..."); print(f"Sender: Waiting for ACCEPT/REJECT...")
        response_header = parse_header(sock, timeout=ACCEPTANCE_TIMEOUT)
        if response_header is None: raise ConnectionAbortedError("No valid response from receiver.")
        response_type = response_header.get('transfer_type')
        if response_type == TRANSFER_TYPE_ACCEPT: print("Sender: Received ACCEPT."); self._send_status("status", f"Sending '{filename}'...")
        elif response_type == TRANSFER_TYPE_REJECT: reason = response_header.get('metadata', {}).get('reason', 'N/A'); raise InterruptedError(f"Rejected by receiver: {reason}")
        else: raise ConnectionAbortedError(f"Unexpected response: {response_type}")

        # 3. Send Payload
        self._check_cancel()
        actual_sent = self._send_payload(sock, self.item, payload_size, filename)
        if actual_sent != payload_size: raise ConnectionAbortedError(f"Payload size mismatch: expected {payload_size}, sent {actual_sent}")
        return True


    def _send_text(self, sock: socket.socket) -> bool:
        """Handles the protocol flow for sending a text snippet."""
        if not self.item or not isinstance(self.item, str): raise TypeError("Text item is not a string.")
        payload_bytes = self.item.encode(HEADER_ENCODING); payload_size = len(payload_bytes)
        header_bytes = create_text_header(payload_bytes)

        # 1. Send Header
        sock.settimeout(HEADER_TIMEOUT); sock.sendall(header_bytes); sock.settimeout(None)
        self._check_cancel()

        # 2. Implicit Acceptance - Send Payload
        self._send_status("status", f"Sending text snippet...")
        actual_sent = self._send_payload(sock, payload_bytes, payload_size, "Text Snippet")
        if actual_sent != payload_size: raise ConnectionAbortedError(f"Text payload size mismatch: expected {payload_size}, sent {actual_sent}")
        return True


    def _send_multi(self, sock: socket.socket) -> bool:
        """Handles the protocol flow for sending multiple files with ACK sync."""
        # --- 0. Validation ---
        if not self.file_list:
            raise ValueError("File list for multi-transfer is empty.")

        # --- 1. Send MULTI_START Header ---
        start_header = create_multi_start_header(self.total_items, self.total_size, self.base_name)
        try:
            sock.settimeout(HEADER_TIMEOUT); sock.sendall(start_header); sock.settimeout(None)
        except (socket.error, ssl.SSLError, socket.timeout) as e:
            raise ConnectionAbortedError(f"Failed to send MULTI_START header: {e}") from e
        self._check_cancel()

        # --- 2. Wait for Batch Acceptance ---
        self._send_status("status", f"Waiting for batch acceptance '{self.base_name}'...")
        print(f"Sender: Waiting for batch ACCEPT/REJECT (timeout={ACCEPTANCE_TIMEOUT}s)...")
        response_header = parse_header(sock, timeout=ACCEPTANCE_TIMEOUT)
        if response_header is None: raise ConnectionAbortedError("No valid batch response from receiver (Timeout/Closed).")
        response_type = response_header.get('transfer_type'); reason = response_header.get('metadata', {}).get('reason', 'N/A')
        if response_type == TRANSFER_TYPE_ACCEPT: print("Sender: Received batch ACCEPT."); self._send_status("status", f"Sending batch '{self.base_name}'...")
        elif response_type == TRANSFER_TYPE_REJECT: raise InterruptedError(f"Batch rejected by receiver: {reason}")
        else: raise ConnectionAbortedError(f"Unexpected batch response: {response_type}. Reason: {reason}")

        # --- 3. Send Individual Files with ACK ---
        bytes_sent_overall = 0; start_time_overall = time.monotonic(); last_update_time_overall = start_time_overall

        for index, (abs_path_str, rel_path_str) in enumerate(self.file_list):
            self._check_cancel(); current_filename = os.path.basename(rel_path_str)
            context_msg = f"{current_filename} ({index+1}/{self.total_items})"
            self._send_status("status", f"Sending: {context_msg}")

            try: # Handle errors for individual files
                abs_path = Path(abs_path_str)
                if not abs_path.is_file(): print(f"Warning: Skipping non-file: {abs_path}"); self._send_status("info", f"Skipped: {current_filename}"); continue
                try: file_size = abs_path.stat().st_size
                except OSError as stat_err: print(f"Warning: Cannot get size for {abs_path}: {stat_err}"); self._send_status("info", f"Skipped: {current_filename}"); continue

                # --- Delay BEFORE sending header (except for first file) ---
                if index > 0: time.sleep(0.05)
                # --- End Delay ---

                # 3a. Send MULTI_FILE Header
                file_header = create_multi_file_header(rel_path_str, file_size)
                sock.settimeout(HEADER_TIMEOUT); sock.sendall(file_header); sock.settimeout(None); self._check_cancel()

                # 3b. Send File Payload
                actual_sent = self._send_payload(sock, abs_path_str, file_size, context_msg)
                if actual_sent != file_size: raise ConnectionAbortedError(f"Payload mismatch for {current_filename}")

                # --- 3c. Wait for ACK ---
                print(f"Sender: Waiting for ACK {index+1}/{self.total_items}..."); sock.settimeout(DATA_TIMEOUT)
                try:
                    ack = sock.recv(1)
                    if not ack: raise ConnectionAbortedError(f"Connection closed waiting for ACK ({current_filename})")
                    if ack != ACK_BYTE: raise ConnectionAbortedError(f"Invalid ACK byte ({ack!r}) after {current_filename}")
                    print(f"Sender: Received ACK {index+1}.")
                except socket.timeout: raise ConnectionAbortedError(f"Timeout waiting for ACK ({current_filename})")
                finally: sock.settimeout(None); self._check_cancel()
                # --- End ACK Wait ---

                # 3d. Update Overall Progress
                bytes_sent_overall += actual_sent; current_time_overall = time.monotonic()
                if current_time_overall - last_update_time_overall >= PROGRESS_UPDATE_INTERVAL or (index + 1 == self.total_items):
                     elapsed = max(0.01, current_time_overall - start_time_overall); speed = bytes_sent_overall / elapsed if elapsed > 0 else 0
                     eta = ((self.total_size - bytes_sent_overall) / speed) if speed > 0 else 0
                     self._send_status("progress", "send", bytes_sent_overall, self.total_size, speed, eta, f"(Overall) {context_msg}")
                     last_update_time_overall = current_time_overall

            # Handle errors for this specific file
            except FileNotFoundError as e: print(f"Warning: {e}. Skipping."); self._send_status("info", f"Skipped: {current_filename}"); continue
            except InterruptedError: raise
            except Exception as e: raise ConnectionAbortedError(f"Error sending file '{current_filename}': {e}") from e # Abort batch

        # --- Loop finished successfully ---

        # 4. Send MULTI_END signal
        self._check_cancel(); end_header = create_multi_end_header()
        try:
            sock.settimeout(HEADER_TIMEOUT); sock.sendall(end_header); sock.settimeout(None); print("Sender: Sent MULTI_END signal.")
        except (socket.error, ssl.SSLError, socket.timeout) as e: print(f"Warning: Failed to send MULTI_END signal: {e}")

        # 5. Final Overall Progress
        if self.total_size >= 0:
             elapsed = max(0.01, time.monotonic() - start_time_overall); speed = bytes_sent_overall / elapsed if elapsed > 0 else 0
             self._send_status("progress", "send", bytes_sent_overall, self.total_size, speed, 0, "(Overall) Complete")
        return True


# --- File Receiver ---
class FileReceiver(TransferAgent):
    """Listens for connections and handles file/text/multi reception."""
    def __init__(self, config: ConfigManager, status_queue: Queue,
                 stop_event: threading.Event, app_logic_ref):
        super().__init__(status_queue, None)
        self.config = config; self.stop_event = stop_event; self.app_logic = app_logic_ref
        self.server_socket = None; self._thread = None; self.active_transfers = {}
        self.use_tls = self.config.get_boolean_setting('Network', 'enable_tls')
        self.ssl_context = None; self.cert_dir = Path(self.config.config_path.parent) / CERT_DIR_NAME
        self.cert_file = self.cert_dir / CERT_FILE_NAME; self.key_file = self.cert_dir / KEY_FILE_NAME
        if self.use_tls:
            self.ssl_context = create_ssl_context(self.cert_dir, self.key_file, self.cert_file, server_side=True)
            if not self.ssl_context: self.use_tls = False; print("Warning: TLS enabled but context failed. Disabling TLS.")

    def _handle_connection(self, raw_client_sock: socket.socket, address: tuple):
        """
        Handles a single incoming client connection in a dedicated thread.
        Manages TLS handshake (if enabled), routes to specific receive logic,
        and performs final cleanup. Cleanup of partially received data is
        delegated to the specific receive methods (_receive_single_file, _receive_multi).
        """
        ip, port = address; addr_str = f"{ip}:{port}"
        print(f"Incoming connection from {addr_str}")
        sock = raw_client_sock # Start with the raw socket
        transfer_cancel_event = threading.Event()
        self.active_transfers[address] = transfer_cancel_event
        # Create a per-transfer agent instance for status reporting and cancellation checks
        agent = TransferAgent(self.status_queue, transfer_cancel_event)

        # State variables specific to this connection handler
        received_items_base_dir = None # Track base dir path only if _receive_multi returns it
        accepted = False # Track if ACCEPT signal was successfully sent
        transfer_type_handled = None # Track the initial transfer type for context

        try:
            # --- 1. Optional TLS Handshake ---
            if self.use_tls:
                 if not self.ssl_context:
                      # This should ideally not happen if constructor logic is sound
                      raise ConnectionAbortedError("Internal Error: TLS enabled but server SSL context missing.")
                 print(f"Attempting TLS handshake with {addr_str}...")
                 try:
                      raw_client_sock.settimeout(HANDSHAKE_TIMEOUT)
                      # wrap_socket performs the handshake
                      sock = self.ssl_context.wrap_socket(
                          raw_client_sock,
                          server_side=True,
                          do_handshake_on_connect=True, # Ensure handshake happens here
                          suppress_ragged_eofs=True # Handle potential unclean TLS closures
                      )
                      sock.settimeout(None) # Reset timeout after successful handshake
                      print(f"TLS handshake successful with {addr_str}. Cipher: {sock.cipher()}")
                 except ssl.SSLError as e:
                      # Catch specific SSL errors during handshake
                      sock.settimeout(None) # Reset timeout on raw socket
                      raise ConnectionAbortedError(f"TLS Handshake failed: {e}") from e
                 except socket.timeout:
                      # Catch timeout specifically during handshake
                      sock.settimeout(None)
                      raise ConnectionAbortedError("TLS Handshake timed out.") from None
                 except Exception as e:
                      # Catch other unexpected errors during TLS setup
                      sock.settimeout(None)
                      raise ConnectionAbortedError(f"Error during TLS wrap/handshake: {e}") from e

            # --- 2. Parse Initial Header from Client ---
            agent._check_cancel() # Check for cancellation before reading header
            # Use a reasonably long timeout for the very first header from client
            header_info = parse_header(sock, timeout=HEADER_TIMEOUT * 2)
            if not header_info:
                 # parse_header logs details of failure (timeout, invalid format, etc.)
                 raise ValueError(f"Invalid or missing initial header from {addr_str}.")

            transfer_type = header_info.get('transfer_type')
            transfer_type_handled = transfer_type # Store for logging/context
            print(f"Received initial header type: {transfer_type} from {addr_str}")

            # --- 3. Route to Specific Handler Based on Type ---
            if transfer_type == TRANSFER_TYPE_FILE:
                # _receive_single_file returns True if ACCEPT was sent successfully
                accepted = self._receive_single_file(agent, sock, header_info, addr_str)
            elif transfer_type == TRANSFER_TYPE_TEXT:
                # _receive_text implicitly accepts
                accepted = self._receive_text(agent, sock, header_info, addr_str)
            elif transfer_type == TRANSFER_TYPE_MULTI_START:
                # _receive_multi returns (accepted_flag, base_dir_path)
                # It handles its own cleanup internally if the *loop* fails after acceptance.
                accepted, received_items_base_dir = self._receive_multi(agent, sock, header_info, addr_str)
            else:
                 # Handle unsupported transfer types
                 reason = f"Unsupported transfer type received: {transfer_type}"
                 print(f"Rejecting connection from {addr_str}: {reason}")
                 try:
                     # Attempt to send rejection notice
                     sock.sendall(create_reject_header(reason))
                 except Exception as send_e:
                     print(f"Error sending REJECT for unknown type: {send_e}")
                 # Raise error to stop processing this connection
                 raise ValueError(reason)

            # If execution reaches here without exceptions, the transfer was handled successfully
            # by the specific sub-method (_receive_single_file, _receive_text, or _receive_multi).
            # The 'complete' status message is sent by those methods.

        # --- Centralized Exception Handling for the Connection ---
        except InterruptedError as e:
             # Handles cancellation initiated locally or by receiver rejection
             error_msg = f"Transfer cancelled or rejected: {e}"; print(f"{error_msg} (from {addr_str})")
             # Send 'cancel' status *only if* the transfer was initially accepted
             if accepted: agent._send_status("error", "cancel", error_msg)
             # *** No batch cleanup call here - handled within _receive_multi's except block ***
        except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError) as e:
             # Handle specific socket timeouts or SSL non-blocking issues if they escape lower levels
             error_msg = f"Socket Timeout/SSLWant Error: {e}"; print(f"{error_msg} (from {addr_str})")
             agent._send_status("error", "receive", error_msg)
             # *** No batch cleanup call here ***
        except (socket.error, ssl.SSLError, ConnectionAbortedError, ConnectionResetError, ValueError, OSError) as e:
             # Handles network errors, protocol violations (ValueError), filesystem issues (OSError)
             error_msg = f"Receive Error: {e}"; print(f"{error_msg} (from {addr_str})")
             agent._send_status("error", "receive", error_msg)
             # *** No batch cleanup call here ***
        except Exception as e:
             # Catch any other unexpected errors during connection handling
             error_msg = f"Unexpected error handling connection: {e}"
             print(f"ERROR: {error_msg} (from {addr_str})\n{traceback.format_exc()}")
             agent._send_status("error", "receive", error_msg)
             # *** No batch cleanup call here ***
        finally:
             # --- Final Cleanup Actions for this Connection ---
             print(f"Starting final cleanup for connection from {addr_str}")
             # Gracefully close the socket
             if sock:
                 print("  Closing socket...")
                 try: sock.shutdown(socket.SHUT_RDWR)
                 except Exception: pass # Ignore errors if already closed/invalid
                 try: sock.close()
                 except Exception: pass
                 print("  Socket closed.")
             elif raw_client_sock: # Close raw socket if TLS wrap failed before sock was assigned
                 print("  Closing raw socket...")
                 try: raw_client_sock.shutdown(socket.SHUT_RDWR)
                 except Exception: pass
                 try: raw_client_sock.close()
                 except Exception: pass
                 print("  Raw socket closed.")

             # Remove transfer from the active tracking dictionary
             if address in self.active_transfers:
                 print(f"  Removing active transfer entry for {addr_str}")
                 del self.active_transfers[address]

             # Clean up confirmation result from AppLogic's dictionary
             if addr_str in self.app_logic.confirmation_results:
                 try:
                     del self.app_logic.confirmation_results[addr_str]
                     print(f"  Cleaned up confirmation result for {addr_str}")
                 except KeyError:
                     pass # Ignore if already removed

             print(f"Finished cleanup for connection from {addr_str}.")
             # End of the handler thread for this connection


    def _receive_single_file(self, agent: TransferAgent, sock: socket.socket, header_info: dict, addr_str: str) -> bool:
        """Handles receiving a single file."""
        metadata = header_info.get('metadata', {}); filename = metadata.get('filename'); data_size = header_info.get('data_size', 0)
        if not filename or data_size < 0: raise ValueError("Invalid FILE header.")

        accepted = False; target_filepath = None
        try: # Wrap confirmation and reception
            if self.config.get_boolean_setting('Preferences', 'confirm_receive'):
                event = threading.Event(); agent._send_status("confirm_receive", filename, data_size, addr_str, event, False)
                print(f"Waiting user confirm for '{filename}'..."); confirmed = event.wait(300.0) and self.app_logic.get_confirmation_result(addr_str)
                if not confirmed: reason = "Rejected" if confirmed else "Timeout"; sock.sendall(create_reject_header(reason)); raise InterruptedError(reason)
            print(f"Receiver: Sending ACCEPT for '{filename}'..."); sock.sendall(create_accept_header()); accepted = True

            dl_dir = Path(self.config.get_setting('Preferences', 'downloads_directory'))
            if not dl_dir.is_dir(): dl_dir = Path(self.config._defaults['Preferences']['downloads_directory']); dl_dir.mkdir(parents=True, exist_ok=True)
            target_filepath = Path(generate_unique_filepath(str(dl_dir), filename)); target_filename = target_filepath.name
            agent._send_status("status", f"Receiving '{target_filename}'..."); print(f"Receiving -> '{target_filepath}'")

            bytes_received = 0; start_time = time.monotonic(); last_update = start_time
            with open(target_filepath, 'wb') as f:
                while bytes_received < data_size:
                    agent._check_cancel()
                    remaining = data_size - bytes_received; read_size = min(BUFFER_SIZE, remaining)
                    if read_size <= 0: break
                    sock.settimeout(DATA_TIMEOUT); chunk = sock.recv(read_size); sock.settimeout(None)
                    if not chunk: raise ConnectionAbortedError("Connection closed mid-file.")
                    f.write(chunk); bytes_received += len(chunk)
                    now = time.monotonic()
                    if now - last_update >= PROGRESS_UPDATE_INTERVAL or bytes_received == data_size:
                        elapsed=max(0.01,now-start_time); speed=bytes_received/elapsed; eta=((data_size-bytes_received)/speed) if speed>0 else 0
                        agent._send_status("progress","receive",bytes_received,data_size,speed,eta,target_filename); last_update=now

            if bytes_received != data_size: raise ValueError(f"Size mismatch: Got {bytes_received}, expected {data_size}")
            if target_filepath.stat().st_size != data_size: raise ValueError("Disk size mismatch")

            agent._send_status("complete", "receive", f"File '{target_filename}' received."); print(f"Success: '{target_filename}'")
            return accepted # Indicate success
        except Exception as e:
            if accepted and target_filepath and target_filepath.exists(): self._cleanup_partial_file(str(target_filepath))
            raise # Re-raise for outer handler

    def _receive_text(self, agent: TransferAgent, sock: socket.socket, header_info: dict, addr_str: str) -> bool:
        """Handles receiving a text snippet."""
        data_size = header_info.get('data_size', 0)
        if data_size < 0: raise ValueError("Invalid text size.")
        accepted = True # Implicit accept
        agent._send_status("status", f"Receiving text snippet ({data_size}b)...")
        text_bytes = b''; bytes_received = 0; sock.settimeout(DATA_TIMEOUT)
        try:
            while bytes_received < data_size:
                agent._check_cancel()
                remaining = data_size - bytes_received; read_size = min(BUFFER_SIZE, remaining)
                if read_size <= 0: break
                chunk = sock.recv(read_size)
                if not chunk: raise ConnectionAbortedError("Connection closed mid-text.")
                text_bytes += chunk; bytes_received += len(chunk)
        finally: sock.settimeout(None)
        if bytes_received != data_size: raise ValueError(f"Text size mismatch: Got {bytes_received}, expected {data_size}")

        received_text = text_bytes.decode(HEADER_ENCODING); print(f"Received text: {received_text[:100]}...")
        agent._send_status("text_received", received_text, addr_str)
        agent._send_status("complete", "receive", f"Text snippet received from {addr_str}.")
        return accepted

    def _receive_multi(self, agent: TransferAgent, sock: socket.socket, header_info: dict, addr_str: str) -> tuple[bool, Path | None]:
        """
        Handles receiving multiple files/folder contents with ACK synchronization.
        Performs its own cleanup of the created batch directory if the receiving
        loop fails after acceptance.

        Args:
            agent: The TransferAgent instance for this specific connection.
            sock: The connected socket object.
            header_info: The parsed MULTI_START header dictionary.
            addr_str: The string representation of the client address.

        Returns:
            A tuple (accepted_flag, base_dir_path). base_dir_path is None if
            acceptance/directory creation failed. accepted_flag is True if
            ACCEPT was sent.

        Raises:
            InterruptedError: If transfer is rejected or cancelled.
            OSError: If directory preparation fails.
            ConnectionAbortedError, socket.error, ssl.SSLError, ValueError: On protocol/network errors.
        """
        # --- 1. Extract Metadata & Validate ---
        metadata = header_info.get('metadata', {})
        total_items = metadata.get('total_items', 0)
        total_size = metadata.get('total_size', 0)
        base_name = metadata.get('base_name', 'Received_Batch')
        if total_items <= 0 or total_size < 0:
            raise ValueError(f"Invalid MULTI_START header data received: items={total_items}, size={total_size}")

        # --- 2. State Initialization ---
        accepted = False # Track if ACCEPT signal was sent
        receive_base_dir = None # Track the path if directory is created

        # --- 3. Confirmation Step ---
        if self.config.get_boolean_setting('Preferences', 'confirm_receive'):
            confirmation_result_event = threading.Event()
            # Send request to AppLogic/UI
            agent._send_status("confirm_receive", base_name, total_size, addr_str, confirmation_result_event, True, total_items)
            print(f"Waiting user confirmation for batch '{base_name}' ({total_items} items) from {addr_str}...")
            # Wait for UI response via event (with timeout)
            confirmed_in_time = confirmation_result_event.wait(timeout=300.0)
            user_confirmed = confirmed_in_time and self.app_logic.get_confirmation_result(addr_str)

            if not user_confirmed:
                 reason = "Rejected by user" if confirmed_in_time else "Confirmation timeout"
                 print(f"Receive {reason.lower()} for batch '{base_name}'.")
                 try: sock.sendall(create_reject_header(reason)) # Try to notify sender
                 except Exception: pass # Ignore errors sending reject
                 raise InterruptedError(reason) # Signal rejection internally

        # --- 4. Send ACCEPT Signal ---
        # If confirmation passed or was disabled, send ACCEPT
        print(f"Receiver: Sending batch ACCEPT for '{base_name}' to {addr_str}")
        try:
            sock.sendall(create_accept_header())
            accepted = True # Mark as accepted only after successful send
        except (socket.error, ssl.SSLError) as e:
            raise ConnectionAbortedError(f"Failed to send batch ACCEPT signal: {e}") from e

        # --- 5. Prepare Base Directory ---
        try:
            downloads_dir = Path(self.config.get_setting('Preferences', 'downloads_directory'))
            # Validate downloads_dir and attempt fallback/creation if necessary
            if not downloads_dir.is_dir():
                 fallback_path = Path(self.config._defaults['Preferences']['downloads_directory'])
                 print(f"Warning: Invalid downloads dir: {downloads_dir}. Using fallback: {fallback_path}")
                 downloads_dir = fallback_path
                 try: downloads_dir.mkdir(parents=True, exist_ok=True)
                 except OSError as mk_err: raise OSError(f"Cannot create fallback directory {downloads_dir}: {mk_err}") from mk_err

            # Sanitize base name and create unique directory name
            safe_base_name = "".join(c for c in base_name if c.isalnum() or c in (' ', '-', '_')).strip() or "Received_Batch"
            sender_id = addr_str.split(':')[0].replace('.', '_') # Basic ID from IP
            batch_dir_name = f"{sender_id}_{safe_base_name}"
            receive_base_dir = Path(generate_unique_filepath(str(downloads_dir), batch_dir_name))

            # Create the final unique directory
            receive_base_dir.mkdir(parents=True, exist_ok=False)
            print(f"Created batch directory: {receive_base_dir}")
        except Exception as dir_err:
            # Raise error if directory prep fails - caught by _handle_connection
            raise OSError(f"Failed to prepare receive directory: {dir_err}") from dir_err


        # --- 6. Receive Files Loop ---
        bytes_rx_overall = 0; items_rx_count = 0
        start_time = time.monotonic(); last_update = start_time

        # Wrap the core receiving loop in try/except to handle internal failures
        # and perform cleanup if necessary *within this function*.
        try:
            while items_rx_count < total_items:
                agent._check_cancel() # Check for cancellation/shutdown before each header/payload

                # --- 6a. Parse Header for Next Item ---
                print(f"Receiver: Waiting for header {items_rx_count+1}/{total_items}...")
                file_header = parse_header(sock, timeout=HEADER_TIMEOUT * 2) # Allow more time between files
                if file_header is None:
                    raise ConnectionAbortedError(f"Timeout or invalid header received while waiting for file item {items_rx_count + 1}.")

                header_type = file_header.get('transfer_type')

                # --- Handle MULTI_FILE Header ---
                if header_type == TRANSFER_TYPE_MULTI_FILE:
                    items_rx_count += 1 # Increment count now we know it's a file
                    # Extract and validate metadata
                    meta = file_header.get('metadata', {}); rel_path_str = meta.get('relative_path'); file_size = file_header.get('data_size', -1)
                    if not rel_path_str or file_size < 0:
                        raise ValueError(f"Invalid MULTI_FILE header data for item {items_rx_count}.")

                    # Construct and sanitize target path
                    rel_path = Path(rel_path_str)
                    if rel_path.is_absolute() or any(p == '..' for p in rel_path.parts):
                        raise ValueError(f"Security Error: Received invalid relative path '{rel_path_str}'")
                    target_fp = receive_base_dir / rel_path
                    filename = target_fp.name
                    ctx = f"{filename} ({items_rx_count}/{total_items})"

                    # Ensure parent directories exist
                    try: target_fp.parent.mkdir(parents=True, exist_ok=True)
                    except OSError as e: raise OSError(f"Cannot create subdirs for {target_fp}: {e}") from e

                    # Log and update status
                    agent._send_status("status", f"Receiving: {ctx}")
                    print(f"Receiving {items_rx_count}/{total_items}: '{rel_path_str}' ({file_size}b) -> '{target_fp}'")

                    # --- 6b. Receive File Payload ---
                    bytes_rx_file = 0
                    try: # Separate try/except for file IO and socket reads
                        with open(target_fp, 'wb') as f:
                            while bytes_rx_file < file_size:
                                agent._check_cancel()
                                remain = file_size - bytes_rx_file; read_size = min(BUFFER_SIZE, remain)
                                if read_size <= 0: break # Safety break
                                sock.settimeout(DATA_TIMEOUT); chunk = sock.recv(read_size); sock.settimeout(None)
                                if not chunk: raise ConnectionAbortedError(f"Connection closed receiving {filename}")
                                f.write(chunk); bytes_rx_file += len(chunk)
                        # Explicit check after loop finishes
                        if bytes_rx_file != file_size: raise ValueError(f"Payload size mismatch for '{filename}'")
                    except Exception as payload_err:
                         print(f"Payload Error for {filename}: {payload_err}")
                         raise payload_err # Re-raise to be caught by outer loop handler

                    # --- 6c. Verify Disk Size (Optional but recommended) ---
                    try:
                        if target_fp.stat().st_size != file_size: raise ValueError(f"Disk size mismatch for '{filename}' after write")
                    except OSError as stat_err: raise OSError(f"Cannot stat received file '{filename}'") from stat_err

                    # --- 6d. Send ACK to Sender ---
                    print(f"Receiver: Sending ACK {items_rx_count} for {filename}..."); sock.settimeout(DATA_TIMEOUT)
                    try: sock.sendall(ACK_BYTE)
                    except Exception as ack_err: raise ConnectionAbortedError(f"Failed to send ACK for {filename}: {ack_err}") from ack_err
                    finally: sock.settimeout(None)
                    print(f"Receiver: ACK {items_rx_count} sent.")

                    # --- 6e. Update Overall Progress ---
                    bytes_rx_overall += bytes_rx_file; now = time.monotonic()
                    if now - last_update >= PROGRESS_UPDATE_INTERVAL or items_rx_count == total_items:
                        elapsed = max(0.01, now - start_time); speed = bytes_rx_overall / elapsed if elapsed > 0 else 0
                        eta = ((total_size - bytes_rx_overall) / speed) if speed > 0 else 0
                        agent._send_status("progress", "receive", bytes_rx_overall, total_size, speed, eta, f"(Overall) {ctx}")
                        last_update = now

                # --- Handle MULTI_END Header ---
                elif header_type == TRANSFER_TYPE_MULTI_END:
                    print("Receiver: Received MULTI_END signal.")
                    # Final validation: Check if item count matches
                    if items_rx_count != total_items:
                        raise ValueError(f"Item count mismatch: Expected {total_items}, received {items_rx_count} before MULTI_END.")
                    break # Successful completion of the loop

                # --- Handle Unexpected Header Type ---
                else:
                    raise ValueError(f"Protocol Error: Unexpected header type '{header_type}' received during batch transfer.")

            # --- Loop finished successfully (MULTI_END received and item count matched) ---
            print(f"Multi-receive loop completed successfully for batch '{base_name}'.")
            # Final overall progress update
            elapsed = max(0.01, time.monotonic() - start_time); speed = bytes_rx_overall / elapsed if elapsed > 0 else 0
            agent._send_status("progress", "receive", bytes_rx_overall, total_size, speed, 0, "(Overall) Complete")
            # Send completion status to UI/AppLogic
            agent._send_status("complete", "receive", f"Batch '{base_name}' ({total_items} items) received successfully.")
            print(f"Success: Batch '{base_name}' ({items_rx_count}/{total_items} items).") # Final success log
            return accepted, receive_base_dir # Return success state

        except Exception as loop_err:
            # --- Catch errors specifically from the file receiving loop ---
            print(f"Error occurred during multi-receive loop for batch '{base_name}': {loop_err}")
            # Perform cleanup *because the loop failed*
            if receive_base_dir: # Check if directory was created before cleaning
                 self._cleanup_partial_batch(receive_base_dir)
            # Re-raise the exception to be handled by _handle_connection's general error reporting
            # This ensures the correct error status is sent to the UI
            raise loop_err

    def _cleanup_partial_file(self, filepath):
        """Removes a partially received single file."""
        try:
            if filepath and Path(filepath).exists():
                print(f"Cleaning up partial file: {filepath}")
                os.remove(filepath)
                print(f"Removed: {filepath}")
        except OSError as e: print(f"Error removing partial file '{filepath}': {e}")

    def _cleanup_partial_batch(self, dirpath: Path | None):
        """Removes the entire directory created for a partial/failed batch."""
        # Called ONLY from _handle_connection's except blocks OR _receive_multi's inner except block
        if dirpath and isinstance(dirpath, Path) and dirpath.exists() and dirpath.is_dir():
             print(f"Attempting to remove incomplete/failed batch directory: {dirpath}")
             try:
                 shutil.rmtree(dirpath) # Recursively remove directory
                 print(f"Removed batch directory: {dirpath}")
             except OSError as remove_err:
                 print(f"Could not remove batch directory '{dirpath}': {remove_err}")
        elif dirpath:
             # Log if called with a path that doesn't exist or isn't a directory
             print(f"Skipping batch cleanup (directory not found or invalid): {dirpath}")

    def _run_server(self):
        """Main server loop to listen for and accept connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', APP_PORT))
            self.server_socket.listen(5) # Listen backlog
            self.server_socket.settimeout(1.0) # Timeout for accept() to allow checking stop_event
            protocol = "TLS" if self.use_tls else "TCP"
            print(f"Receiver listening on port {APP_PORT} ({protocol})...")
            self._send_status("status", f"Listening ({protocol})")

            while not self.stop_event.is_set():
                try:
                    # Wait for a connection with timeout
                    client_socket, address = self.server_socket.accept()
                    # Start a handler thread for the new connection
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address),
                        name=f"Handler-{address[0]}:{address[1]}", # Give thread a name
                        daemon=True
                    )
                    handler_thread.start()
                except socket.timeout:
                    continue # Normal, just check stop_event again
                except ssl.SSLError as e:
                    # Catch TLS errors during the accept/initial handshake phase
                    print(f"SSL Error during accept/handshake: {e}")
                except Exception as e:
                    # Log other unexpected errors during accept
                    if not self.stop_event.is_set(): # Avoid logging errors during shutdown
                          print(f"Error accepting connection: {e}")
                          # Maybe rate-limit error reporting if it keeps happening
                          time.sleep(0.5)

        except OSError as e:
             # Error binding to port (e.g., port already in use)
             error_msg = f"Could not bind receiver to port {APP_PORT}: {e}"
             print(f"ERROR: {error_msg}")
             self._send_status("error","server", error_msg)
        except Exception as e:
             # Catch-all for errors in the server setup/loop itself
             error_msg = f"Unexpected error in receiver server thread: {e}"
             print(f"ERROR: {error_msg}\n{traceback.format_exc()}")
             self._send_status("error","server", error_msg)
        finally:
            # --- Server Shutdown Cleanup ---
            print("Receiver server thread shutting down...")
            # Signal any active connection handlers to cancel
            active_addrs = list(self.active_transfers.keys())
            if active_addrs:
                 print(f"Signalling {len(active_addrs)} active handler(s) to cancel...")
                 for addr in active_addrs:
                      if addr in self.active_transfers:
                           try: self.active_transfers[addr].set() # Set cancel event
                           except Exception as set_err: print(f"Error setting cancel event for {addr}: {set_err}")
            # Close the main server socket
            if self.server_socket:
                print("Closing server socket...")
                try: self.server_socket.close()
                except Exception as e: print(f"Error closing server socket: {e}")
            self.server_socket = None
            self._send_status("status", "Receiver stopped.")
            print("Receiver server thread finished.")


    def start(self):
        """Starts the receiver server thread."""
        # Basic check for downloads directory validity on start
        try:
            dl_path = Path(self.config.get_setting('Preferences','downloads_directory'))
            if not dl_path.is_dir(): print(f"Warning: Invalid downloads directory '{dl_path}' in config.")
        except Exception as e: print(f"Warning: Error checking downloads directory on start: {e}")

        # Start thread only if not already running
        if self._thread is None or not self._thread.is_alive():
            print("Starting receiver thread...")
            # Reset stop event in case of restart? Ensure it's clear.
            self.stop_event.clear()
            self._thread = threading.Thread(target=self._run_server, name="ReceiverThread", daemon=True)
            self._thread.start()
        else:
            print("Receiver thread already running.")

    def shutdown(self):
        """Requests receiver shutdown by setting the stop event."""
        if self._thread and self._thread.is_alive():
            print("Requesting receiver shutdown...")
            self.stop_event.set() # Signal the main loop and handlers via _check_cancel()
            # Wait briefly for the thread to potentially finish? Optional.
            # self._thread.join(timeout=1.5)
        else:
             print("Receiver shutdown requested, but thread wasn't running.")

    def cancel_transfer(self, address_tuple):
        """Requests cancellation for a specific transfer handler thread via its event."""
        if address_tuple in self.active_transfers:
            print(f"Requesting cancellation for transfer handler {address_tuple}");
            try:
                self.active_transfers[address_tuple].set() # Signal the specific handler
                return True
            except Exception as e:
                 print(f"Error setting cancel event for {address_tuple}: {e}")
                 return False
        else:
            print(f"No active transfer handler found for address {address_tuple} to cancel.")
            return False

    def _cleanup_partial_file(self, filepath):
        """Removes a partially received single file."""
        try:
            if filepath and Path(filepath).exists(): print(f"Cleaning up partial file: {filepath}"); os.remove(filepath)
        except OSError as e: print(f"Error removing partial file '{filepath}': {e}")

    def _cleanup_partial_batch(self, dirpath: Path | None):
        """Removes the entire directory for a partial/failed batch."""
        # Called ONLY from _handle_connection's except blocks now
        if dirpath and isinstance(dirpath, Path) and dirpath.exists() and dirpath.is_dir():
             print(f"Cleaning up partial batch directory: {dirpath}")
             try: shutil.rmtree(dirpath)
             except OSError as e: print(f"Error removing batch dir '{dirpath}': {e}")

    def _run_server(self):
        """Main server loop to listen for and accept connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', APP_PORT)); self.server_socket.listen(5); self.server_socket.settimeout(1.0)
            protocol = "TLS" if self.use_tls else "TCP"; print(f"Receiver listening on port {APP_PORT} ({protocol})..."); self._send_status("status", f"Listening ({protocol})")
            while not self.stop_event.is_set():
                try:
                    client_socket, address = self.server_socket.accept()
                    handler = threading.Thread(target=self._handle_connection, args=(client_socket, address), daemon=True)
                    handler.start()
                except socket.timeout: continue
                except ssl.SSLError as e: print(f"SSL Error during accept: {e}")
                except Exception as e:
                     if not self.stop_event.is_set(): print(f"Error accepting connection: {e}"); time.sleep(0.5)
        except OSError as e: error_msg = f"Bind Error port {APP_PORT}: {e}"; print(f"ERROR: {error_msg}"); self._send_status("error","server", error_msg)
        except Exception as e: error_msg = f"Receiver thread error: {e}"; print(f"ERROR: {error_msg}\n{traceback.format_exc()}"); self._send_status("error","server", error_msg)
        finally:
            print("Receiver server thread shutting down..."); active = list(self.active_transfers.keys())
            if active: print(f"Signalling {len(active)} handlers..."); [self.active_transfers[addr].set() for addr in active if addr in self.active_transfers]
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass
            self.server_socket = None; self._send_status("status", "Receiver stopped."); print("Receiver server thread finished.")

    def start(self):
        """Starts the receiver server thread."""
        try: dl_path=Path(self.config.get_setting('Preferences','downloads_directory')); # Check dir
        except Exception as e: print(f"Warning: Error checking download dir: {e}")
        if self._thread is None or not self._thread.is_alive():
            print("Starting receiver thread..."); self.stop_event.clear()
            self._thread = threading.Thread(target=self._run_server, name="ReceiverThread", daemon=True); self._thread.start()
        else: print("Receiver thread already running.")

    def shutdown(self):
        """Requests receiver shutdown."""
        if self._thread and self._thread.is_alive(): print("Requesting receiver shutdown..."); self.stop_event.set()
        else: print("Receiver shutdown requested, but thread not running.")

    def cancel_transfer(self, address_tuple):
        """Requests cancellation for a specific transfer handler thread."""
        if address_tuple in self.active_transfers: print(f"Requesting cancel for {address_tuple}"); self.active_transfers[address_tuple].set(); return True
        else: print(f"No active handler for {address_tuple} to cancel."); return False

import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import filedialog
from tkinter import messagebox
import time
import sys  # For platform check
import os   # For basename

# Conditional pyperclip import for text popup copy button
try:
    import pyperclip
except ImportError:
    pyperclip = None
    # print("Warning (UI): 'pyperclip' not installed. Copy button will be disabled.")

# Use constants
try:
    # Import relevant types, including MULTI_START for clarity if needed elsewhere
    from ..utils.constants import TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT, TRANSFER_TYPE_MULTI_START
except ImportError:
    # Fallback values if constants not found (less ideal)
    TRANSFER_TYPE_FILE = "FILE"
    TRANSFER_TYPE_TEXT = "TEXT"
    TRANSFER_TYPE_MULTI_START = "MULTI_START" # Needed if logic refers to it

# Map sys.platform to short codes for device list display
OS_MAP = {
    'win32': '[Win]',
    'linux': '[Lin]',
    'darwin': '[Mac]',
}


class MainWindow:
    """Handles the Tkinter GUI elements and forwards actions to the controller."""

    def __init__(self, root, controller):
        self.root = root
        self.controller = controller # Instance of AppLogic
        self.root.title("LanDrop")
        # Adjusted size for new buttons/label
        self.root.geometry("550x600")
        self.root.minsize(450, 500)

        # --- Styling ---
        style = ttk.Style(self.root)
        try: # Apply a preferred theme if available
            themes = style.theme_names()
            if 'clam' in themes: style.theme_use('clam')
            elif 'vista' in themes: style.theme_use('vista') # Good on Windows
            elif 'aqua' in themes: style.theme_use('aqua') # Good on macOS
        except tk.TclError: print("Could not set a preferred theme, using default.")

        # --- Main Layout: Paned Window ---
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned_window.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        # --- Top Frame (Discovery & Actions) ---
        self.top_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(self.top_frame, weight=3) # Give more initial height

        # Grid configuration for resizing within top_frame
        self.top_frame.rowconfigure(1, weight=1) # Device list row expands vertically
        self.top_frame.columnconfigure(0, weight=1) # Device list column expands horizontally
        self.top_frame.columnconfigure(1, weight=0) # Text input column has fixed initial width

        # Device Discovery List
        devices_label = ttk.Label(self.top_frame, text="Discovered Devices:")
        devices_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 2))

        listbox_frame = ttk.Frame(self.top_frame) # Frame to hold listbox + scrollbar
        listbox_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        listbox_frame.rowconfigure(0, weight=1); listbox_frame.columnconfigure(0, weight=1)
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.devices_listbox = tk.Listbox( listbox_frame, height=8, yscrollcommand=scrollbar.set, exportselection=False )
        scrollbar.config(command=self.devices_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns") # Scrollbar right
        self.devices_listbox.grid(row=0, column=0, sticky="nsew") # Listbox left, expands
        self.devices_listbox.bind('<<ListboxSelect>>', self._on_device_select_ui) # Event binding

        # Text Input Area
        text_input_frame = ttk.LabelFrame(self.top_frame, text="Text Snippet", padding=5)
        text_input_frame.grid(row=1, column=1, sticky="nsew", pady=(0,0))
        text_input_frame.rowconfigure(0, weight=1); text_input_frame.columnconfigure(0, weight=1)
        self.text_input = scrolledtext.ScrolledText( text_input_frame, height=5, width=25, wrap=tk.WORD )
        self.text_input.grid(row=0, column=0, sticky="nsew")
        self.text_input.bind("<KeyRelease>", self._on_text_change) # Update state on key release

        # Selection Status Label
        self.selection_label = ttk.Label(self.top_frame, text="Nothing selected", wraplength=300)
        self.selection_label.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 2))

        # Action Buttons Frame
        action_frame = ttk.Frame(self.top_frame)
        action_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        self.select_files_button = ttk.Button( action_frame, text="Select Files...", command=self._select_files_ui )
        self.select_files_button.pack(side=tk.LEFT, padx=(0, 5))
        self.select_folder_button = ttk.Button( action_frame, text="Select Folder...", command=self._select_folder_ui )
        self.select_folder_button.pack(side=tk.LEFT, padx=(0, 5))
        self.send_button = ttk.Button( action_frame, text="Send ->", command=self._send_data_ui, state=tk.DISABLED )
        self.send_button.pack(side=tk.LEFT, padx=(0, 5))
        self.cancel_button = ttk.Button( action_frame, text="Cancel", command=self._cancel_transfer_ui, state=tk.DISABLED )
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 5))

        # Progress Bar
        self.progress_bar = ttk.Progressbar( self.top_frame, orient=tk.HORIZONTAL, length=100, mode='determinate' )
        self.progress_bar.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(5, 5))
        self.progress_bar['value'] = 0

        # --- Bottom Frame (History) ---
        self.bottom_frame = ttk.LabelFrame(self.paned_window, text="History", padding=5)
        self.paned_window.add(self.bottom_frame, weight=1) # Less initial height
        self.bottom_frame.rowconfigure(0, weight=1); self.bottom_frame.columnconfigure(0, weight=1)
        self.history_text = scrolledtext.ScrolledText( self.bottom_frame, height=6, width=60, wrap=tk.WORD, state=tk.DISABLED )
        self.history_text.grid(row=0, column=0, sticky="nsew")

        # --- Status Bar ---
        self.status_label = ttk.Label( self.root, text="Status: Initializing...", relief=tk.SUNKEN, anchor=tk.W, padding="2 5" )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Internal state tracking
        self.last_explicit_selection_type = None # Helps prioritize send logic

        # Window close handling
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close_request)

    # --- Helper Methods for Formatting ---
    def _format_speed(self, bytes_per_second):
        if bytes_per_second < 1024: return f"{bytes_per_second:.1f} B/s"
        elif bytes_per_second < 1024**2: return f"{bytes_per_second/1024:.1f} KB/s"
        elif bytes_per_second < 1024**3: return f"{bytes_per_second/1024**2:.1f} MB/s"
        else: return f"{bytes_per_second/1024**3:.1f} GB/s"

    def _format_eta(self, seconds):
        if not isinstance(seconds, (int, float)) or seconds < 0 or seconds > 3600 * 24 * 7: return "--:--"
        try:
            (mins, secs) = divmod(int(seconds), 60); (hours, mins) = divmod(mins, 60)
            return f"{hours:d}:{mins:02d}:{secs:02d}" if hours > 0 else f"{mins:02d}:{secs:02d}"
        except Exception: return "--:--"

    def _format_size(self, size_bytes):
        if size_bytes < 1024: return f"{size_bytes} B"
        elif size_bytes < 1024**2: return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3: return f"{size_bytes/1024**2:.2f} MB"
        else: return f"{size_bytes/1024**3:.2f} GB"

    # --- Private UI Event Handlers ---
    def _select_files_ui(self):
        """Handles 'Select Files...' button click."""
        # Returns tuple of paths, or empty tuple if cancelled
        filepaths = filedialog.askopenfilenames(title="Select Files to Send")
        if filepaths: # Check if user selected files
            self.last_explicit_selection_type = 'files'
            if hasattr(self, 'text_input'): self.text_input.delete('1.0', tk.END)
            self.controller.handle_folder_selection(None) # Clear folder selection
            self.update_selection_display(f"{len(filepaths)} files selected")
            self.controller.handle_files_selection(filepaths) # Notify controller
        self.reset_progress()

    def _select_folder_ui(self):
        """Handles 'Select Folder...' button click."""
        # Returns path string, or empty string if cancelled
        folderpath = filedialog.askdirectory(title="Select Folder to Send")
        if folderpath: # Check if user selected a folder
            self.last_explicit_selection_type = 'folder'
            if hasattr(self, 'text_input'): self.text_input.delete('1.0', tk.END)
            self.controller.handle_files_selection(None) # Clear files selection
            folder_name = os.path.basename(folderpath) or folderpath # Handle root dir case
            self.update_selection_display(f"Folder: {folder_name}")
            self.controller.handle_folder_selection(folderpath) # Notify controller
        self.reset_progress()

    def _on_text_change(self, event=None):
        """Handles text input changes, potentially clearing other selections."""
        if hasattr(self, 'text_input'):
            text_content = self.text_input.get("1.0", tk.END).strip()
            if text_content:
                # If user types, make text the primary intended selection
                if self.last_explicit_selection_type != 'text':
                    self.last_explicit_selection_type = 'text'
                    self.controller.handle_files_selection(None)
                    self.controller.handle_folder_selection(None)
                    self.update_selection_display("Text snippet entered")
            # Update button enable/disable state based on current validity
            self.controller.check_send_button_state_external()

    def _on_device_select_ui(self, event=None):
        """Handles listbox selection change."""
        selected_indices = self.devices_listbox.curselection()
        if selected_indices:
            try:
                full_display_name = self.devices_listbox.get(selected_indices[0])
                # Extract name before potential OS tag " [...]"
                tag_index = full_display_name.rfind(' [')
                selected_name = full_display_name[:tag_index] if tag_index != -1 else full_display_name
                self.controller.handle_device_selection(selected_name)
            except (tk.TclError, IndexError): self.controller.handle_device_selection(None) # Handle errors/empty list
        else: self.controller.handle_device_selection(None) # No selection

    def _send_data_ui(self):
        """
        Determine what to send (files, folder, text) based on controller state,
        disable the Send button immediately, and initiate the send request.
        Re-enables Send button if validation fails before sending.
        """

        # --- Immediately Disable Send Button ---
        # Prevent rapid re-clicks before controller state updates the UI.
        can_proceed = True # Flag to track if we should proceed
        try:
            if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                # Check current state to avoid unnecessary config calls if already disabled
                if str(self.send_button.cget('state')) != str(tk.DISABLED):
                    self.send_button.config(state=tk.DISABLED)
            else:
                # If button doesn't exist, we can't proceed reliably
                can_proceed = False
                print("Warning: Send button not found in _send_data_ui.")

        except tk.TclError:
             # Window might be closing
             can_proceed = False

        # If button disable failed or button doesn't exist, exit early
        if not can_proceed:
            return

        # --- Determine What to Send ---
        send_type = None
        item_to_send = None

        # Get current selection state directly from the controller
        # This ensures we use the authoritative state, not just the UI widgets' content.
        selected_files = self.controller.selected_filepaths
        selected_folder = self.controller.selected_folderpath
        text_content = self.controller.selected_text # Use text from controller state

        # Determine transfer type and item based on controller state
        # Priority: Files > Folder > Text (adjust if needed)
        if selected_files:
            if len(selected_files) == 1:
                # Exactly one file selected via "Select Files..." -> Single file transfer
                send_type = TRANSFER_TYPE_FILE
                item_to_send = selected_files[0] # Send the single path string
                print("DEBUG UI: Sending as SINGLE FILE")
            else:
                # Multiple files selected -> Multi-file transfer
                send_type = TRANSFER_TYPE_MULTI_START
                item_to_send = selected_files # Send the list/tuple of paths
                print("DEBUG UI: Sending as MULTI FILES")
        elif selected_folder:
            # Folder selected -> Multi-file transfer (folder contents)
            send_type = TRANSFER_TYPE_MULTI_START
            item_to_send = selected_folder # Send the folder path string
            print("DEBUG UI: Sending as FOLDER")
        elif text_content:
            # Text entered and active -> Text transfer
            send_type = TRANSFER_TYPE_TEXT
            item_to_send = text_content # Send the text string
            print("DEBUG UI: Sending as TEXT")

        # --- Initiate Send or Handle Failure ---
        if send_type and item_to_send:
             # Valid item selected, proceed with send request
             self.reset_progress() # Clear progress bar
             # Controller will set is_transfer_active and manage button state via updates
             self.controller.handle_send_request(item_to_send, send_type)
        else:
             # No valid item was determined (e.g., selection cleared between clicks)
             # Show an error message
             self.show_error("Send Error", "Select files, a folder, or enter text to send.")

             # --- Re-enable Send Button on Validation Failure ---
             # Since we disabled it at the start but didn't actually start a transfer,
             # we need to re-enable it here.
             try:
                 if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                      # Only re-enable if controller confirms no transfer is active
                      # (Safer check than just assuming) - Although controller state might
                      # not have updated yet if error is very fast. Let's just enable.
                      self.send_button.config(state=tk.NORMAL)
             except tk.TclError:
                  pass # Window might be closing
             except Exception as e:
                  print(f"Error re-enabling send button after validation fail: {e}")

    def _cancel_transfer_ui(self):
        """Handles 'Cancel' button click."""
        self.controller.handle_cancel_request()

    def _handle_close_request(self):
        """Handles window close button click."""
        print("UI: Close button clicked. Requesting shutdown...")
        self.controller.handle_shutdown()

    # --- Public Methods (called by Controller via root.after) ---
    def update_status(self, message):
        """Updates the text in the status bar."""
        try:
             if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                  self.status_label.config(text=f"Status: {message}")
        except tk.TclError: pass # Ignore if closing

    def update_selection_display(self, message):
        """Updates the label showing the current selection."""
        try:
            if hasattr(self, 'selection_label') and self.selection_label.winfo_exists():
                self.selection_label.config(text=message)
        except tk.TclError: pass

    def update_device_list(self, action, display_name, os_info=""):
        """Adds or removes a device display name from the listbox."""
        if not display_name: return
        os_tag = OS_MAP.get(os_info, f"[{os_info[:3]}]" if os_info else "")
        full_display_name = f"{display_name} {os_tag}".strip()
        try:
            if not hasattr(self, 'devices_listbox') or not self.devices_listbox.winfo_exists(): return
            items = list(self.devices_listbox.get(0, tk.END))
            selected_idx = self.devices_listbox.curselection()
            selected_name_full = self.devices_listbox.get(selected_idx[0]) if selected_idx else None

            if action == "add" and full_display_name not in items:
                self.devices_listbox.insert(tk.END, full_display_name)
            elif action == "remove":
                found_idx, item_to_remove_full = -1, None
                for idx, item in enumerate(items):
                    if item.startswith(display_name + " [") or item == display_name:
                        found_idx, item_to_remove_full = idx, item; break
                if found_idx != -1:
                    self.devices_listbox.delete(found_idx)
                    if item_to_remove_full == selected_name_full:
                        self.controller.handle_device_selection(None) # Clear controller state
        except tk.TclError: pass
        except Exception as e: print(f"Unexpected error updating device list: {e}")

    def update_button_states(self, send_enabled, cancel_enabled):
         """Updates Send/Cancel/Select button states."""
         try:
             # Determine desired states
             send_state = tk.NORMAL if send_enabled else tk.DISABLED
             cancel_state = tk.NORMAL if cancel_enabled else tk.DISABLED
             edit_state = tk.NORMAL if not cancel_enabled else tk.DISABLED # Disable selects during transfer
             text_state = tk.NORMAL if not cancel_enabled else tk.DISABLED

             # Update buttons only if state needs changing
             if hasattr(self, 'send_button') and self.send_button.winfo_exists() and str(self.send_button.cget('state')) != str(send_state):
                 self.send_button.config(state=send_state)
             if hasattr(self, 'cancel_button') and self.cancel_button.winfo_exists() and str(self.cancel_button.cget('state')) != str(cancel_state):
                 self.cancel_button.config(state=cancel_state)
             if hasattr(self, 'select_files_button') and self.select_files_button.winfo_exists() and str(self.select_files_button.cget('state')) != str(edit_state):
                 self.select_files_button.config(state=edit_state)
             if hasattr(self, 'select_folder_button') and self.select_folder_button.winfo_exists() and str(self.select_folder_button.cget('state')) != str(edit_state):
                 self.select_folder_button.config(state=edit_state)
             if hasattr(self, 'text_input') and self.text_input.winfo_exists() and str(self.text_input.cget('state')) != str(text_state):
                 self.text_input.config(state=text_state)
         except tk.TclError: pass
         except Exception as e: print(f"Unexpected error updating button states: {e}")

    def show_error(self, title, message):
        """Displays an error message box via main thread."""
        print(f"UI Error: {title} - {message}")
        try: self.root.after(0, lambda t=title, m=message: messagebox.showerror(t, m, parent=self.root))
        except Exception as e: print(f"Failed to show error messagebox: {e}")
        self.reset_progress() # Reset progress on error

    def show_success(self, title, message):
         """Displays a success/info message box via main thread."""
         print(f"UI Success: {title} - {message}")
         try: self.root.after(0, lambda t=title, m=message: messagebox.showinfo(t, m, parent=self.root))
         except Exception as e: print(f"Failed to show info messagebox: {e}")
         self.reset_progress() # Reset progress on success

    def ask_confirmation(self, title, message):
         """Shows a yes/no dialog. Must be called from main thread."""
         return messagebox.askyesno(title, message, parent=self.root) # Make modal to main window

    def show_selectable_text_popup(self, title, text_content):
        """Creates a Toplevel window with selectable text and a copy button."""
        print(f"UI Displaying selectable text: {title}")
        try:
            popup = tk.Toplevel(self.root); popup.title(title)
            popup.geometry("450x300"); popup.minsize(300, 200)
            try: popup.transient(self.root) # Associate with main window
            except tk.TclError: pass # Ignore if main window gone
            popup.grab_set() # Make modal

            main_frame = ttk.Frame(popup, padding=10); main_frame.pack(expand=True, fill=tk.BOTH)
            main_frame.rowconfigure(0, weight=1); main_frame.columnconfigure(0, weight=1)

            text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=10, width=50)
            text_widget.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
            text_widget.insert(tk.END, text_content); text_widget.config(state=tk.DISABLED)

            button_frame = ttk.Frame(main_frame); button_frame.grid(row=1, column=0, sticky="e")

            def _copy_to_clipboard():
                if pyperclip:
                    try:
                        pyperclip.copy(text_widget.get("1.0", tk.END).strip())
                        copy_button.config(text="Copied!", state=tk.DISABLED)
                        popup.after(1500, lambda: copy_button.config(text="Copy", state=tk.NORMAL if pyperclip else tk.DISABLED))
                    except Exception as e: messagebox.showerror("Clipboard Error", f"Could not copy text:\n{e}", parent=popup)
                else: messagebox.showwarning("Clipboard Unavailable", "Cannot copy text: 'pyperclip' module not installed.", parent=popup)

            copy_button = ttk.Button(button_frame, text="Copy", command=_copy_to_clipboard, state=(tk.NORMAL if pyperclip else tk.DISABLED))
            copy_button.pack(side=tk.LEFT, padx=(0, 5))
            close_button = ttk.Button(button_frame, text="Close", command=popup.destroy); close_button.pack(side=tk.LEFT)

            # Center popup
            popup.update_idletasks()
            root_x, root_y = self.root.winfo_x(), self.root.winfo_y(); root_w, root_h = self.root.winfo_width(), self.root.winfo_height()
            popup_w, popup_h = popup.winfo_width(), popup.winfo_height()
            x = root_x + (root_w // 2) - (popup_w // 2); y = root_y + (root_h // 2) - (popup_h // 2)
            popup.geometry(f'+{x}+{y}')

            popup.focus_set(); text_widget.focus_set() # Focus text for selection
            self.root.wait_window(popup) # Wait for popup to close

        except tk.TclError as e: print(f"Failed text popup (window closed?): {e}")
        except Exception as e: print(f"Unexpected error text popup: {e}\n{traceback.format_exc()}")

    def update_progress(self, current_bytes, total_bytes, speed_bps, eta_sec, context_msg=""):
        """Updates the progress bar and status text."""
        try:
            if not hasattr(self, 'progress_bar') or not self.progress_bar.winfo_exists(): return
            if total_bytes > 0:
                percentage = int((current_bytes / total_bytes) * 100)
                safe_percentage = max(0, min(100, percentage))
                self.progress_bar['value'] = safe_percentage
                speed_str = self._format_speed(speed_bps); eta_str = self._format_eta(eta_sec)
                status = f"Progress: {safe_percentage}% ({speed_str}, ETA: {eta_str})"
                if context_msg: status += f" - {context_msg}"
                self.update_status(status)
            else: # Handle 0-byte transfers or initial state
                self.progress_bar['value'] = 0
                status = "Progress: Calculating..." if not (total_bytes == 0 and current_bytes == 0) else "Progress: 0 bytes"
                if context_msg: status += f" - {context_msg}"
                self.update_status(status)
        except tk.TclError: pass
        except Exception as e: print(f"Error updating progress: {e}")

    def reset_progress(self):
        """Resets the progress bar to 0 via main thread."""
        def _do_reset():
            try:
                if hasattr(self, 'progress_bar') and self.progress_bar.winfo_exists():
                    self.progress_bar.config(value=0)
            except tk.TclError: pass
            except Exception as e: print(f"Error resetting progress bar: {e}")
        self.root.after(0, _do_reset)

    def add_history_log(self, log_message):
        """Adds a timestamped message to the history text widget via main thread."""
        def _update_history():
            try:
                if hasattr(self, 'history_text') and self.history_text.winfo_exists():
                    self.history_text.config(state=tk.NORMAL)
                    timestamp = time.strftime("%H:%M:%S", time.localtime())
                    self.history_text.insert(tk.END, f"{timestamp} - {log_message}\n")
                    self.history_text.see(tk.END) # Auto-scroll
                    self.history_text.config(state=tk.DISABLED)
            except tk.TclError: pass
            except Exception as e: print(f"Unexpected error updating history log: {e}")
        self.root.after(0, _update_history)

    def destroy_window(self):
        """Safely destroys the Tkinter root window."""
        print("UI: Received request to destroy window.")
        try:
            if self.root and self.root.winfo_exists():
                self.root.destroy()
                print("UI: Window destroyed.")
            else: print("UI: Window already destroyed or invalid.")
        except tk.TclError as e: print(f"Error during window destruction: {e}")
        except Exception as e: print(f"Unexpected error destroying window: {e}")