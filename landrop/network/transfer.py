import socket
import threading
import os
import time
from queue import Queue

# Use relative imports
from .protocol import create_header, parse_header
from ..utils.file_utils import generate_unique_filepath
from ..constants import APP_PORT

BUFFER_SIZE = 4096 # 4KB chunks for sending/receiving

class FileSender:
    """Handles sending a single file to a peer."""
    def __init__(self, host: str, port: int, filepath: str, status_queue: Queue):
        self.host = host
        self.port = port
        self.filepath = filepath
        self.status_queue = status_queue
        self.filename = os.path.basename(filepath)

    def _send_status(self, message_type: str, message: str):
        """Helper to put status updates onto the queue."""
        try:
            self.status_queue.put((message_type, message))
        except Exception as e:
            print(f"Error sending status to queue: {e}")

    def send(self):
        """Connects to the receiver and sends the file."""
        try:
            file_size = os.path.getsize(self.filepath)
            self._send_status("status", f"Connecting to {self.host}:{self.port}...")

            # Create connection (with timeout)
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                self._send_status("status", f"Connected. Preparing to send {self.filename} ({file_size} bytes)...")

                # 1. Create and send header
                header_bytes = create_header("FILE", self.filename, file_size)
                sock.sendall(header_bytes)
                # print(f"Debug: Sent header ({len(header_bytes)} bytes)") # Debug

                # 2. Send file data
                self._send_status("status", f"Sending {self.filename}...")
                bytes_sent = 0
                with open(self.filepath, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break # End of file
                        sock.sendall(chunk)
                        bytes_sent += len(chunk)
                        # Add progress reporting here if desired, e.g.:
                        # self._send_status("progress", "send", bytes_sent, file_size)

                # Ensure all data is sent before declaring success
                # sock.shutdown(socket.SHUT_WR) # Signal end of sending - might not be needed with context manager

                self._send_status("complete", f"File '{self.filename}' sent successfully.")
                print(f"Successfully sent {self.filename} ({bytes_sent}/{file_size} bytes) to {self.host}:{self.port}")
                return True, f"Sent '{self.filename}'"

        except FileNotFoundError:
            error_msg = f"File not found: {self.filepath}"
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
            return False, error_msg
        except socket.timeout:
            error_msg = f"Connection to {self.host}:{self.port} timed out."
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
            return False, error_msg
        except socket.error as e:
            error_msg = f"Network error sending to {self.host}:{self.port}: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error sending file: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
            return False, error_msg


class FileReceiver:
    """Listens for incoming connections and handles file reception."""
    def __init__(self, downloads_dir: str, status_queue: Queue, stop_event: threading.Event):
        self.downloads_dir = downloads_dir
        self.status_queue = status_queue
        self.stop_event = stop_event
        self.server_socket = None
        self._thread = None

    def _send_status(self, message_type: str, message: str):
        """Helper to put status updates onto the queue."""
        try:
            self.status_queue.put((message_type, message))
        except Exception as e:
            print(f"Error sending status to queue: {e}")

    def _handle_connection(self, client_socket: socket.socket, address: tuple):
        """Handles a single incoming client connection."""
        ip, port = address
        print(f"Incoming connection from {ip}:{port}")
        try:
            # 1. Parse header
            header_info = parse_header(client_socket)
            if not header_info:
                self._send_status("error", f"Invalid header received from {ip}.")
                return

            transfer_type = header_info.get('transfer_type')
            metadata = header_info.get('metadata', {})
            filename = metadata.get('filename')
            data_size = header_info.get('data_size')

            if transfer_type != "FILE" or not filename or data_size is None:
                self._send_status("error", f"Malformed header data from {ip}.")
                print(f"Malformed header: Type={transfer_type}, Filename={filename}, Size={data_size}")
                return

            # Check for potentially malicious filenames (basic check)
            if ".." in filename or "/" in filename or "\\" in filename:
                 self._send_status("error", f"Rejected potentially unsafe filename '{filename}' from {ip}.")
                 print(f"Rejected unsafe filename: {filename}")
                 return


            # 2. Determine save path and open file
            target_filepath = generate_unique_filepath(self.downloads_dir, filename)
            target_filename = os.path.basename(target_filepath) # Get final filename
            self._send_status("status", f"Receiving '{target_filename}' ({data_size} bytes) from {ip}...")
            print(f"Receiving '{filename}' ({data_size} bytes) from {ip}:{port}. Saving to '{target_filepath}'")

            bytes_received = 0
            with open(target_filepath, 'wb') as f:
                # 3. Receive data in chunks
                while bytes_received < data_size:
                    bytes_to_read = min(BUFFER_SIZE, data_size - bytes_received)
                    chunk = client_socket.recv(bytes_to_read)
                    if not chunk:
                        # Connection closed prematurely
                        raise socket.error("Connection closed unexpectedly by sender.")
                    f.write(chunk)
                    bytes_received += len(chunk)
                    # Add progress reporting here if desired
                    # self._send_status("progress", "receive", bytes_received, data_size)


            # Verification (optional but good)
            if bytes_received != data_size:
                 final_size = os.path.getsize(target_filepath)
                 raise ValueError(f"Incomplete transfer: Expected {data_size} bytes, received {bytes_received}, file size is {final_size}")

            self._send_status("complete", f"File '{target_filename}' received successfully.")
            print(f"Successfully received '{target_filename}' ({bytes_received} bytes). Saved to {self.downloads_dir}")

        except socket.error as e:
            error_msg = f"Network error receiving from {ip}: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
            # Attempt to clean up incomplete file
            if 'target_filepath' in locals() and os.path.exists(target_filepath):
                try: os.remove(target_filepath)
                except OSError: print(f"Could not remove incomplete file: {target_filepath}")
        except OSError as e:
            error_msg = f"File system error receiving '{filename}': {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
        except Exception as e:
            error_msg = f"Unexpected error handling connection from {ip}: {e}"
            print(f"Error: {error_msg}")
            self._send_status("error", error_msg)
            if 'target_filepath' in locals() and os.path.exists(target_filepath) and 'bytes_received' in locals() and bytes_received != data_size:
                try: os.remove(target_filepath)
                except OSError: print(f"Could not remove potentially corrupt file: {target_filepath}")
        finally:
            # Ensure socket is closed
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass # Ignore errors if socket already closed
            client_socket.close()
            print(f"Connection from {ip}:{port} closed.")

    def _run_server(self):
        """Internal method to run the listening server in a thread."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow reusing the address quickly after shutdown
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to all interfaces on the specified port
            self.server_socket.bind(('0.0.0.0', APP_PORT))
            self.server_socket.listen(5) # Allow up to 5 queued connections
             # Set a timeout so accept() doesn't block forever, allows checking stop_event
            self.server_socket.settimeout(1.0)

            print(f"Receiver listening on port {APP_PORT}...")
            self._send_status("status", f"Listening for incoming files on port {APP_PORT}")

            while not self.stop_event.is_set():
                try:
                    client_socket, address = self.server_socket.accept()
                    # Create a new thread to handle this client, so the server
                    # can immediately go back to listening for more connections.
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address),
                        daemon=True # Allow app to exit even if handlers are running (though they should finish quickly)
                    )
                    handler_thread.start()
                except socket.timeout:
                    # This is expected when no connection comes in within the timeout period.
                    # Allows the loop to check self.stop_event.
                    continue
                except Exception as e:
                    # Catch errors during accept (rare)
                     if not self.stop_event.is_set(): # Avoid logging errors during shutdown
                         print(f"Error accepting connection: {e}")
                         self._send_status("error", f"Server accept error: {e}")
                         time.sleep(1) # Avoid busy-looping on persistent accept errors

        except OSError as e:
            # Handle case where port might already be in use
             error_msg = f"Could not bind receiver to port {APP_PORT}. Is another instance running? Error: {e}"
             print(f"Error: {error_msg}")
             self._send_status("error", error_msg)
        except Exception as e:
             error_msg = f"Unexpected error in receiver server thread: {e}"
             print(f"Error: {error_msg}")
             if not self.stop_event.is_set(): # Avoid logging errors during shutdown
                 self._send_status("error", error_msg)
        finally:
            print("Receiver server thread shutting down...")
            if self.server_socket:
                try:
                    self.server_socket.close()
                    print("Receiver socket closed.")
                except Exception as e:
                    print(f"Error closing receiver socket: {e}")
            self.server_socket = None # Clear reference
            self._send_status("status", "Receiver stopped.")
            print("Receiver server thread finished.")


    def start(self):
        """Starts the receiver server in a background thread."""
        if not self.downloads_dir:
            print("Cannot start receiver: Downloads directory not set.")
            return

        if self._thread is None or not self._thread.is_alive():
            print("Starting receiver thread...")
            # stop_event should be managed by AppLogic
            # self.stop_event.clear() # Ensure clear before start
            self._thread = threading.Thread(target=self._run_server, daemon=True)
            self._thread.start()
        else:
             print("Receiver thread already running.")

    def shutdown(self):
        """Signals the receiver thread to stop and closes the socket."""
        if self._thread and self._thread.is_alive():
            print("Requesting receiver shutdown...")
            # stop_event is set by AppLogic, no need to set here
            # self.stop_event.set() # Signal the loop to exit

            # The server thread will close its own socket in the finally block
            # Optionally force close here if needed, but can cause issues
            # if self.server_socket:
            #    try: self.server_socket.close()
            #    except: pass

            # Don't join here, let AppLogic manage shutdown timing
            # self._thread.join(timeout=2.0)
            # if self._thread.is_alive():
            #     print("Warning: Receiver thread did not exit cleanly.")
        else:
            print("Receiver shutdown requested, but thread wasn't running.")