import queue
import threading
import os

# Use relative imports within the package
from ..network.discovery import NetworkDiscovery
from ..network.transfer import FileSender, FileReceiver
from ..utils.file_utils import find_downloads_folder, generate_unique_filepath
from ..constants import SERVICE_TYPE, APP_PORT, APP_NAME

class AppLogic:
    """Coordinates UI events, network discovery, file transfer, and application state."""
    def __init__(self, root):
        self.root = root
        self.main_window = None
        self.discovered_services = {}
        self.selected_filepath = None
        self.selected_device_display_name = None
        self.discovery_queue = queue.Queue()
        self.transfer_queue = queue.Queue() # Queue for transfer status/progress/completion
        self.stop_event = threading.Event()
        self.network_discovery = NetworkDiscovery(self.discovery_queue, self.stop_event)
        self.file_receiver = None
        self.downloads_dir = find_downloads_folder()
        # --- Add state to track if transfer is active ---
        self.is_transfer_active = False

        if self.downloads_dir:
            print(f"AppLogic: Downloads folder found at: {self.downloads_dir}")
            self.file_receiver = FileReceiver(
                self.downloads_dir,
                self.transfer_queue, # Pass the single queue
                self.stop_event
            )
        else:
            print("AppLogic Error: Could not find Downloads folder.")


    def set_main_window(self, window):
        """Stores a reference to the UI window object."""
        self.main_window = window
        if not self.downloads_dir and self.main_window:
             # Use the new method for showing errors
             self.main_window.show_error("Configuration Error",
                 "Could not determine Downloads folder.\nFile reception is disabled.")


    def start(self):
        """Starts background processes and the update queue polling."""
        print("AppLogic: Starting...")
        self.network_discovery.start()

        if self.file_receiver:
            self.file_receiver.start()
            print("AppLogic: File receiver started.")
        else:
             if self.main_window: self.main_window.update_status("Warning: Cannot receive files (Downloads folder missing).")

        self._poll_queues()


    def _poll_queues(self):
        """Periodically checks discovery and transfer queues for messages."""
        # --- Process Discovery Queue ---
        try:
            while not self.discovery_queue.empty():
                message = self.discovery_queue.get_nowait()
                # ... (discovery queue processing remains the same) ...
                action = message[0]

                if not self.main_window: continue

                if action == "status":
                    # Only update status bar if no transfer is active
                    if not self.is_transfer_active:
                        status_msg = message[1]
                        self.root.after(0, lambda m=status_msg: self.main_window.update_status(m))


                elif action == "add":
                    full_service_name, info = message[1], message[2]
                    if full_service_name != self.network_discovery.get_advertised_name():
                        self.discovered_services[full_service_name] = info
                        display_name = full_service_name.replace("." + SERVICE_TYPE, "")
                        # Use root.after for thread safety
                        self.root.after(0, lambda d=display_name: self.main_window.update_device_list("add", d))

                elif action == "remove":
                    full_service_name = message[1]
                    if full_service_name in self.discovered_services:
                        display_name = full_service_name.replace("." + SERVICE_TYPE, "")
                        del self.discovered_services[full_service_name]
                         # Use root.after for thread safety
                        self.root.after(0, lambda d=display_name: self.main_window.update_device_list("remove", d))

                        if self.selected_device_display_name == display_name:
                            self.selected_device_display_name = None
                            self._check_send_button_state() # Update button state (runs in main thread via root.after below)

        except queue.Empty:
            pass

        # --- Process Transfer Queue ---
        try:
             while not self.transfer_queue.empty():
                message = self.transfer_queue.get_nowait()
                action = message[0]
                op_type = message[1] # 'send', 'receive', 'server', or general status message

                if not self.main_window: continue

                if action == "status":
                    status_msg = message[1] # Here op_type is the message
                    # Only update status bar if no transfer is active OR if it's a transfer status
                    if not self.is_transfer_active or op_type in ['send', 'receive']:
                        self.root.after(0, lambda m=status_msg: self.main_window.update_status(m))

                elif action == "progress":
                    # message = ('progress', 'send'/'receive', current, total, speed, eta)
                    self.is_transfer_active = True # Mark transfer as active
                    _op, current, total, speed, eta = message[1:]
                    self.root.after(0, lambda c=current, t=total, s=speed, e=eta: self.main_window.update_progress(c, t, s, e))
                    # Disable send button during transfer
                    self.root.after(0, lambda: self.main_window.update_send_button_state(False))

                elif action == "complete":
                    # message = ('complete', 'send'/'receive', success_msg)
                    self.is_transfer_active = False # Mark transfer as finished
                    success_msg = message[2]
                    title = "Transfer Complete"
                    # Show success pop-up
                    self.root.after(0, lambda t=title, m=success_msg: self.main_window.show_success(t, m))
                    # Update status bar and reset progress
                    self.root.after(0, lambda m=success_msg: self.main_window.update_status(f"Complete: {m}"))
                    self.root.after(0, self.main_window.reset_progress)
                    # Re-enable send button
                    self._check_send_button_state() # Schedules button update

                elif action == "error":
                    # message = ('error', 'send'/'receive'/'server', error_msg)
                    self.is_transfer_active = False # Mark transfer as finished (due to error)
                    error_msg = message[2]
                    title = f"{op_type.capitalize()} Error"
                    # Show error pop-up
                    self.root.after(0, lambda t=title, m=error_msg: self.main_window.show_error(t, m))
                    # Update status bar and reset progress
                    self.root.after(0, lambda m=error_msg: self.main_window.update_status(f"Error: {m}"))
                    self.root.after(0, self.main_window.reset_progress)
                    # Re-enable send button
                    self._check_send_button_state() # Schedules button update


        except queue.Empty:
             pass
        except IndexError:
             print(f"Warning: Received malformed message in transfer queue: {message}") # Debug
        except Exception as e:
             print(f"Error processing transfer queue: {e}")

        finally:
            self.root.after(150, self._poll_queues) # Reschedule polling


    def _check_send_button_state(self):
        """Determines if the send button should be enabled. Runs via root.after."""
        # Enabled only if file/device selected AND no transfer is active
        enabled = bool(self.selected_filepath and self.selected_device_display_name and not self.is_transfer_active)
        if self.main_window:
            # Schedule the UI update to happen in the main thread
            self.root.after(0, lambda en=enabled: self.main_window.update_send_button_state(en))

    # --- Event Handlers (Called by MainWindow) ---

    def handle_file_selection(self, filepath):
        """Processes file selection from the UI."""
        self.selected_filepath = filepath
        if filepath:
            filename = os.path.basename(filepath)
            if self.main_window:
                 # Update status only if no transfer active
                 if not self.is_transfer_active:
                      self.root.after(0, lambda f=filename: self.main_window.update_status(f"Selected: {f}"))
        else:
             if self.main_window and not self.is_transfer_active:
                 self.root.after(0, lambda: self.main_window.update_status("File selection cancelled."))
        self._check_send_button_state()

    def handle_device_selection(self, display_name):
        """Processes device selection from the UI."""
        self.selected_device_display_name = display_name
        self._check_send_button_state()

    def handle_send_request(self):
        """Handles the user clicking the 'Send' button."""
        if self.is_transfer_active:
             self.main_window.show_error("Busy", "Another transfer is already in progress.")
             return
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
            self.main_window.show_error("Send Error", msg)
            # Schedule UI list refresh potentially removing the stale entry
            self.root.after(0, lambda d=self.selected_device_display_name: self.main_window.update_device_list("remove", d))
            self.selected_device_display_name = None
            self._check_send_button_state()
            return

        try:
            if not target_info.parsed_addresses():
                 raise ValueError("No parsed addresses found.")
            ip_address = target_info.parsed_addresses()[0]
            port = target_info.port

            print(f"Logic: Preparing to send '{self.selected_filepath}' to {self.selected_device_display_name} at {ip_address}:{port}")
            # Initial status update before starting thread
            self.root.after(0, lambda: self.main_window.update_status(f"Initiating send to {self.selected_device_display_name}..."))
            self.is_transfer_active = True # Mark as active early
            self._check_send_button_state() # Disable button immediately

            sender = FileSender(
                host=ip_address,
                port=port,
                filepath=self.selected_filepath,
                status_queue=self.transfer_queue
            )
            send_thread = threading.Thread(target=sender.send, daemon=True)
            send_thread.start()

        # ... (rest of error handling remains similar, ensure errors are shown via show_error) ...
        except (IndexError, ValueError, AttributeError) as e:
             error_msg = f"Could not get valid connection details for '{self.selected_device_display_name}'. Error: {e}"
             self.main_window.show_error("Send Error", error_msg)
             self.is_transfer_active = False # Reset flag on error
             self._check_send_button_state()
        except FileNotFoundError:
             error_msg = f"Selected file not found: {self.selected_filepath}"
             self.main_window.show_error("Send Error", error_msg)
             self.selected_filepath = None
             self.is_transfer_active = False
             self._check_send_button_state()
             # Also update status bar
             self.root.after(0, lambda: self.main_window.update_status("Error: Selected file not found."))
        except Exception as e:
             error_msg = f"An unexpected error occurred preparing the send: {e}"
             self.main_window.show_error("Send Error", error_msg)
             self.is_transfer_active = False
             self._check_send_button_state()

    def handle_shutdown(self):
        """Initiates the application shutdown sequence."""
        print("AppLogic: Handling shutdown request...")
        if self.main_window:
             # Use root.after to ensure UI updates happen before threads might be fully stopped
             self.root.after(0, lambda: self.main_window.update_send_button_state(False))
             self.root.after(0, lambda: self.main_window.update_status("Shutting down..."))

        self.stop_event.set()
        self.network_discovery.shutdown()
        if self.file_receiver:
            self.file_receiver.shutdown()

        print("AppLogic: Scheduling UI destruction.")
        self.root.after(400, self._destroy_ui) # Slightly longer delay


    def _destroy_ui(self):
        """Destroys the main UI window."""
        print("AppLogic: Destroying UI.")
        if self.main_window:
            try:
                # Check if root window still exists before destroying
                if self.root.winfo_exists():
                    self.main_window.destroy_window()
            except Exception as e:
                print(f"Error destroying window: {e}")
        print("AppLogic: UI should be destroyed.")