import queue
import threading
import os # Needed for path operations

# Use relative imports within the package
from ..network.discovery import NetworkDiscovery
from ..network.transfer import FileSender, FileReceiver
from ..utils.file_utils import find_downloads_folder, generate_unique_filepath
from ..constants import SERVICE_TYPE, APP_PORT, APP_NAME

class AppLogic:
    """Coordinates UI events, network discovery, file transfer, and application state."""
    def __init__(self, root):
        self.root = root # Tkinter root needed for scheduling UI updates
        self.main_window = None # UI window reference

        # --- Application State ---
        self.discovered_services = {} # Stores {full_service_name: ServiceInfo}
        self.selected_filepath = None
        self.selected_device_display_name = None # UI display name (e.g., "LanDrop_MyPC")

        # --- Communication & Control ---
        self.discovery_queue = queue.Queue() # Queue for discovery updates
        self.transfer_queue = queue.Queue() # Queue for transfer status/progress
        self.stop_event = threading.Event() # Signals background threads to stop

        # --- Modules ---
        self.network_discovery = NetworkDiscovery(self.discovery_queue, self.stop_event)
        self.file_receiver = None
        self.downloads_dir = find_downloads_folder()

        if self.downloads_dir:
            print(f"AppLogic: Downloads folder found at: {self.downloads_dir}")
            self.file_receiver = FileReceiver(
                self.downloads_dir,
                self.transfer_queue,
                self.stop_event
            )
        else:
            print("AppLogic Error: Could not find Downloads folder. Receiving files will fail.")
            # Optionally disable receiving or show a persistent error in UI

    def set_main_window(self, window):
        """Stores a reference to the UI window object."""
        self.main_window = window
        # Show initial error if downloads dir is missing
        if not self.downloads_dir and self.main_window:
             self.main_window.show_error("Configuration Error",
                 "Could not determine Downloads folder.\n"
                 "File reception is disabled.\n"
                 "Please ensure a 'Downloads' folder exists in your home directory.")


    def start(self):
        """Starts background processes and the update queue polling."""
        print("AppLogic: Starting...")
        self.network_discovery.start()

        if self.file_receiver:
            self.file_receiver.start()
            print("AppLogic: File receiver started.")
        else:
             if self.main_window: self.main_window.update_status("Warning: Cannot receive files (Downloads folder missing).")

        # Start polling the queues for updates
        self._poll_queues()


    def _poll_queues(self):
        """Periodically checks both discovery and transfer queues for messages."""
        queue_processed = False # Track if any message was processed

        # --- Process Discovery Queue ---
        try:
            while not self.discovery_queue.empty():
                queue_processed = True
                message = self.discovery_queue.get_nowait()
                action = message[0]

                if not self.main_window: continue # Skip if UI is gone

                if action == "status":
                    status_msg = message[1]
                    self.main_window.update_status(status_msg)

                elif action == "add":
                    full_service_name, info = message[1], message[2]
                    if full_service_name != self.network_discovery.get_advertised_name():
                        self.discovered_services[full_service_name] = info
                        display_name = full_service_name.replace("." + SERVICE_TYPE, "")
                        self.main_window.update_device_list("add", display_name)
                    #else: print(f"Logic: Ignoring self discovery ({full_service_name})") # Debug

                elif action == "remove":
                    full_service_name = message[1]
                    if full_service_name in self.discovered_services:
                        display_name = full_service_name.replace("." + SERVICE_TYPE, "")
                        del self.discovered_services[full_service_name]
                        self.main_window.update_device_list("remove", display_name)
                        if self.selected_device_display_name == display_name:
                            self.selected_device_display_name = None
                            self._check_send_button_state()

        except queue.Empty:
            pass # Normal

        # --- Process Transfer Queue ---
        try:
             while not self.transfer_queue.empty():
                queue_processed = True
                message = self.transfer_queue.get_nowait()
                action = message[0]
                # print(f"Debug: Transfer Queue Message: {message}") # Debug

                if not self.main_window: continue # Skip if UI is gone

                if action == "status":
                    status_msg = message[1]
                    self.main_window.update_status(status_msg)
                elif action == "error":
                    error_msg = message[1]
                    self.main_window.update_status(f"Error: {error_msg}")
                    self.main_window.show_error("Transfer Error", error_msg)
                elif action == "complete":
                    success_msg = message[1]
                    self.main_window.update_status(f"Complete: {success_msg}")
                # Add progress handling if implemented in sender/receiver
                # elif action == "progress":
                #     # Example: message = ('progress', 'send', current_bytes, total_bytes)
                #     # Example: message = ('progress', 'receive', current_bytes, total_bytes)
                #     op_type, current, total = message[1], message[2], message[3]
                #     percent = int((current / total) * 100) if total > 0 else 0
                #     direction = "Sending" if op_type == "send" else "Receiving"
                #     self.main_window.update_status(f"{direction}: {percent}% ({current}/{total} bytes)")


        except queue.Empty:
             pass # Normal
        except Exception as e:
             print(f"Error processing transfer queue: {e}") # Log unexpected errors

        finally:
            # Reschedule this method to run again after a short delay
            self.root.after(150, self._poll_queues) # Check queues every 150ms

    def _check_send_button_state(self):
        """Determines if the send button should be enabled."""
        enabled = bool(self.selected_filepath and self.selected_device_display_name)
        if self.main_window:
            self.main_window.update_send_button_state(enabled)

    # --- Event Handlers (Called by MainWindow) ---

    def handle_file_selection(self, filepath):
        """Processes file selection from the UI."""
        self.selected_filepath = filepath
        if filepath:
            filename = os.path.basename(filepath) # More robust way to get filename
            self.main_window.update_status(f"Selected: {filename}")
        else:
             self.main_window.update_status("File selection cancelled.")
        self._check_send_button_state()

    def handle_device_selection(self, display_name):
        """Processes device selection from the UI."""
        self.selected_device_display_name = display_name
        # print(f"Logic: Device selected: '{display_name}'") # Debug
        self._check_send_button_state()

    def handle_send_request(self):
        """Handles the user clicking the 'Send' button."""
        if not self.selected_filepath:
            self.main_window.show_error("Send Error", "Please select a file to send.")
            return
        if not self.selected_device_display_name:
            self.main_window.show_error("Send Error", "Please select a target device.")
            return

        target_service_name = f"{self.selected_device_display_name}.{SERVICE_TYPE}"
        target_info = self.discovered_services.get(target_service_name)

        if not target_info:
            msg = f"Device '{self.selected_device_display_name}' may no longer be available."
            print(f"Logic Error: {msg}")
            self.main_window.show_error("Send Error", msg)
            # Force UI list refresh potentially removing the stale entry
            self.main_window.update_device_list("remove", self.selected_device_display_name)
            self.selected_device_display_name = None
            self._check_send_button_state()
            return

        try:
            # Assuming IPv4 from Zeroconf V4Only setting
            if not target_info.parsed_addresses():
                 raise ValueError("No parsed addresses found in service info.")
            ip_address = target_info.parsed_addresses()[0]
            port = target_info.port

            print(f"Logic: Preparing to send '{self.selected_filepath}' to {self.selected_device_display_name} at {ip_address}:{port}")
            self.main_window.update_status(f"Initiating send to {self.selected_device_display_name}...")

            # Instantiate FileSender
            sender = FileSender(
                host=ip_address,
                port=port,
                filepath=self.selected_filepath,
                status_queue=self.transfer_queue # Pass queue for updates
            )

            # Run send in a separate thread so UI doesn't freeze
            send_thread = threading.Thread(target=sender.send, daemon=True)
            send_thread.start()

            # Disable send button during transfer? Optional, good UX.
            # self.main_window.update_send_button_state(False)


        except (IndexError, ValueError, AttributeError) as e:
             error_msg = f"Could not get valid connection details for '{self.selected_device_display_name}'. Service info might be incomplete. Error: {e}"
             print(f"Logic Error: {error_msg}")
             self.main_window.show_error("Send Error", error_msg)
        except FileNotFoundError:
             error_msg = f"Selected file not found: {self.selected_filepath}"
             print(f"Logic Error: {error_msg}")
             self.main_window.show_error("Send Error", error_msg)
             self.selected_filepath = None # Clear invalid selection
             self._check_send_button_state()
        except Exception as e:
             error_msg = f"An unexpected error occurred preparing the send: {e}"
             print(f"Unexpected error: {error_msg}")
             self.main_window.show_error("Send Error", error_msg)


    def handle_shutdown(self):
        """Initiates the application shutdown sequence."""
        print("AppLogic: Handling shutdown request...")
        if self.main_window:
            self.main_window.update_send_button_state(False)
            self.main_window.update_status("Shutting down...")

        # Signal background threads to stop
        self.stop_event.set()

        # Shutdown discovery first
        self.network_discovery.shutdown()

        # Shutdown receiver server
        if self.file_receiver:
            self.file_receiver.shutdown()

        # Schedule the final UI destruction after a brief delay
        # Allows threads time to react to the stop signal and potentially clean up sockets
        print("AppLogic: Scheduling UI destruction.")
        self.root.after(300, self._destroy_ui) # Slightly longer delay for network cleanup

    def _destroy_ui(self):
        """Destroys the main UI window."""
        print("AppLogic: Destroying UI.")
        if self.main_window:
            try:
                self.main_window.destroy_window()
            except Exception as e:
                print(f"Error destroying window: {e}") # Catch potential errors during shutdown
        print("AppLogic: UI should be destroyed.")