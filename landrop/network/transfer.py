import socket
import threading
import os
import time # Import time
from queue import Queue

# Use relative imports
from .protocol import create_header, parse_header
from ..utils.file_utils import generate_unique_filepath
from ..constants import APP_PORT

BUFFER_SIZE = 4096 * 16 # Increase buffer size for potentially better performance (64KB)
PROGRESS_UPDATE_INTERVAL = 0.25 # Update progress roughly 4 times per second

class FileSender:
    """Handles sending a single file to a peer with progress updates."""
    def __init__(self, host: str, port: int, filepath: str, status_queue: Queue):
        self.host = host
        self.port = port
        self.filepath = filepath
        self.status_queue = status_queue
        self.filename = os.path.basename(filepath)

    def _send_status(self, *args): # Accept variable args for different message types
        """Helper to put status updates onto the queue."""
        try:
            self.status_queue.put(args)
        except Exception as e:
            print(f"Error sending status to queue: {e}")

    def send(self):
        """Connects to the receiver and sends the file with progress."""
        start_time = time.monotonic()
        last_update_time = start_time
        bytes_sent = 0

        try:
            file_size = os.path.getsize(self.filepath)
            self._send_status("status", f"Connecting to {self.host}:{self.port}...")

            with socket.create_connection((self.host, self.port), timeout=15) as sock: # Increased timeout
                self._send_status("status", f"Connected. Preparing to send {self.filename} ({file_size} bytes)...")

                header_bytes = create_header("FILE", self.filename, file_size)
                sock.sendall(header_bytes)

                self._send_status("status", f"Sending {self.filename}...")
                start_time = time.monotonic() # Reset start time after connection/header
                last_update_time = start_time

                with open(self.filepath, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        sock.sendall(chunk)
                        bytes_sent += len(chunk)
                        current_time = time.monotonic()
                        elapsed_time = current_time - start_time

                        # --- Progress Update Logic ---
                        if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_sent == file_size:
                            if elapsed_time > 0:
                                speed_bps = bytes_sent / elapsed_time
                                if speed_bps > 0 and file_size > 0:
                                    remaining_bytes = file_size - bytes_sent
                                    eta_sec = remaining_bytes / speed_bps
                                else:
                                     eta_sec = -1 # Indicate unknown ETA
                            else:
                                speed_bps = 0
                                eta_sec = -1

                            self._send_status("progress", "send", bytes_sent, file_size, speed_bps, eta_sec)
                            last_update_time = current_time
                            # --- End Progress Update ---

                # Final progress update to ensure 100% is shown
                if file_size > 0:
                     elapsed_time = time.monotonic() - start_time
                     speed_bps = bytes_sent / elapsed_time if elapsed_time > 0 else 0
                     self._send_status("progress", "send", bytes_sent, file_size, speed_bps, 0) # ETA is 0

                # Add a small delay before completion message sometimes helps UI catch up
                # time.sleep(0.1)

                self._send_status("complete", "send", f"File '{self.filename}' sent successfully.") # Add type
                print(f"Successfully sent {self.filename} ({bytes_sent}/{file_size} bytes) to {self.host}:{self.port}")
                return True, f"Sent '{self.filename}'"

        except FileNotFoundError:
            error_msg = f"File not found: {self.filepath}"
            print(f"Error: {error_msg}")
            self._send_status("error", "send", error_msg) # Add type
            return False, error_msg
        except socket.timeout:
            error_msg = f"Connection to {self.host}:{self.port} timed out."
            print(f"Error: {error_msg}")
            self._send_status("error", "send", error_msg)
            return False, error_msg
        except (socket.error, ConnectionRefusedError, ConnectionAbortedError, ConnectionResetError) as e:
            error_msg = f"Network error sending to {self.host}:{self.port}: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", "send", error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error sending file: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", "send", error_msg)
            return False, error_msg


class FileReceiver:
    """Listens for incoming connections and handles file reception with progress."""
    def __init__(self, downloads_dir: str, status_queue: Queue, stop_event: threading.Event):
        self.downloads_dir = downloads_dir
        self.status_queue = status_queue
        self.stop_event = stop_event
        self.server_socket = None
        self._thread = None

    def _send_status(self, *args): # Accept variable args
        """Helper to put status updates onto the queue."""
        try:
            self.status_queue.put(args)
        except Exception as e:
            print(f"Error sending status to queue: {e}")

    def _handle_connection(self, client_socket: socket.socket, address: tuple):
        """Handles a single incoming client connection with progress."""
        ip, port = address
        print(f"Incoming connection from {ip}:{port}")
        start_time = time.monotonic()
        last_update_time = start_time
        bytes_received = 0
        target_filepath = None # Initialize for finally block
        data_size = 0 # Initialize

        try:
            header_info = parse_header(client_socket)
            if not header_info:
                self._send_status("error", "receive", f"Invalid header received from {ip}.")
                return

            transfer_type = header_info.get('transfer_type')
            metadata = header_info.get('metadata', {})
            filename = metadata.get('filename')
            data_size = header_info.get('data_size')

            if transfer_type != "FILE" or not filename or data_size is None or data_size < 0:
                self._send_status("error", "receive", f"Malformed header data from {ip}.")
                return

            if ".." in filename or "/" in filename or "\\" in filename:
                 self._send_status("error", "receive", f"Rejected potentially unsafe filename '{filename}' from {ip}.")
                 return

            target_filepath = generate_unique_filepath(self.downloads_dir, filename)
            target_filename = os.path.basename(target_filepath)
            self._send_status("status", f"Receiving '{target_filename}' ({data_size} bytes) from {ip}...")
            print(f"Receiving '{filename}' ({data_size} bytes) from {ip}:{port}. Saving to '{target_filepath}'")

            start_time = time.monotonic() # Reset start time after header processing
            last_update_time = start_time

            with open(target_filepath, 'wb') as f:
                while bytes_received < data_size:
                    # Check stop event during long transfers
                    if self.stop_event.is_set():
                         raise socket.error("Receiver shutdown requested during transfer.")

                    bytes_to_read = min(BUFFER_SIZE, data_size - bytes_received)
                    chunk = client_socket.recv(bytes_to_read)
                    if not chunk:
                        raise socket.error("Connection closed unexpectedly by sender.")
                    f.write(chunk)
                    bytes_received += len(chunk)
                    current_time = time.monotonic()
                    elapsed_time = current_time - start_time

                    # --- Progress Update Logic ---
                    if current_time - last_update_time >= PROGRESS_UPDATE_INTERVAL or bytes_received == data_size:
                        if elapsed_time > 0:
                            speed_bps = bytes_received / elapsed_time
                            if speed_bps > 0 and data_size > 0:
                                remaining_bytes = data_size - bytes_received
                                eta_sec = remaining_bytes / speed_bps
                            else:
                                eta_sec = -1
                        else:
                            speed_bps = 0
                            eta_sec = -1

                        self._send_status("progress", "receive", bytes_received, data_size, speed_bps, eta_sec)
                        last_update_time = current_time
                        # --- End Progress Update ---

            # Final progress update
            if data_size > 0:
                elapsed_time = time.monotonic() - start_time
                speed_bps = bytes_received / elapsed_time if elapsed_time > 0 else 0
                self._send_status("progress", "receive", bytes_received, data_size, speed_bps, 0)

            # Verification
            final_size = os.path.getsize(target_filepath)
            if final_size != data_size:
                 raise ValueError(f"Incomplete/Incorrect transfer: Expected {data_size}, File size is {final_size}")

            # time.sleep(0.1) # Optional delay
            self._send_status("complete", "receive", f"File '{target_filename}' received successfully.")
            print(f"Successfully received '{target_filename}' ({bytes_received} bytes). Saved to {self.downloads_dir}")

        except (socket.error, ConnectionResetError, ConnectionAbortedError, ValueError) as e:
            error_msg = f"Network/Transfer error receiving from {ip}: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", "receive", error_msg)
            # Attempt cleanup only if partially written and error occurred
            if target_filepath and os.path.exists(target_filepath) and bytes_received != data_size :
                try:
                     print(f"Attempting to remove incomplete file: {target_filepath}")
                     os.remove(target_filepath)
                except OSError as remove_err:
                     print(f"Could not remove incomplete file: {remove_err}")
        except OSError as e:
            error_msg = f"File system error receiving: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", "receive", error_msg)
        except Exception as e:
            error_msg = f"Unexpected error handling connection from {ip}: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", "receive", error_msg)
            if target_filepath and os.path.exists(target_filepath) and bytes_received != data_size:
                 try:
                      print(f"Attempting to remove file after unexpected error: {target_filepath}")
                      os.remove(target_filepath)
                 except OSError as remove_err:
                      print(f"Could not remove file: {remove_err}")
        finally:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass
            client_socket.close()
            print(f"Connection from {ip}:{port} closed.")

    def _run_server(self):
        # ... (server setup remains the same) ...
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', APP_PORT))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            print(f"Receiver listening on port {APP_PORT}...")
            self._send_status("status", f"Listening for incoming files on port {APP_PORT}")

            while not self.stop_event.is_set():
                try:
                    client_socket, address = self.server_socket.accept()
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address),
                        daemon=True
                    )
                    handler_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                     if not self.stop_event.is_set():
                         print(f"Error accepting connection: {e}")
                         self._send_status("error", "server", f"Server accept error: {e}")
                         time.sleep(1)

        # ... (rest of the error handling and finally block remains the same) ...
        except OSError as e:
             error_msg = f"Could not bind receiver to port {APP_PORT}. Error: {e}"
             print(f"Error: {error_msg}")
             self._send_status("error","server", error_msg)
        except Exception as e:
             error_msg = f"Unexpected error in receiver server thread: {e}"
             print(f"Error: {error_msg}")
             if not self.stop_event.is_set():
                 self._send_status("error", "server", error_msg)
        finally:
            print("Receiver server thread shutting down...")
            if self.server_socket:
                try:
                    self.server_socket.close()
                    print("Receiver socket closed.")
                except Exception as e:
                    print(f"Error closing receiver socket: {e}")
            self.server_socket = None
            self._send_status("status", "Receiver stopped.")
            print("Receiver server thread finished.")


    def start(self):
        # ... (start logic remains the same) ...
        if not self.downloads_dir:
            print("Cannot start receiver: Downloads directory not set.")
            return
        if self._thread is None or not self._thread.is_alive():
            print("Starting receiver thread...")
            self._thread = threading.Thread(target=self._run_server, daemon=True)
            self._thread.start()
        else:
             print("Receiver thread already running.")


    def shutdown(self):
        # ... (shutdown logic remains the same) ...
        if self._thread and self._thread.is_alive():
            print("Requesting receiver shutdown...")
        else:
            print("Receiver shutdown requested, but thread wasn't running.")