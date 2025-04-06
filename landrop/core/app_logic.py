import tkinter as tk # Now needed for TclError check
import queue
import threading
import os
import sys
from pathlib import Path
import time # For history timestamps
import traceback # For detailed error logging

try:
    import pyperclip # For text copy
except ImportError:
    pyperclip = None
    print("Warning: 'pyperclip' not installed. Cannot copy received text to clipboard.")
    print("Install it using: pip install pyperclip")


# Relative imports
from ..network.discovery import NetworkDiscovery
from ..network.transfer import FileSender, FileReceiver
from ..utils.file_utils import generate_unique_filepath # Keep this specific utility
from ..utils.config_manager import ConfigManager
from ..utils.constants import (SERVICE_TYPE, APP_PORT, APP_NAME,
                        TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT)


class AppLogic:
    """Coordinates UI, network, transfers, history, config, and state."""
    def __init__(self, root, config: ConfigManager): # Pass config manager
        self.root = root
        self.config = config
        self.main_window = None

        # State
        self.discovered_services = {} # {full_service_name: (info_obj, os_info)}
        self.selected_filepath = None
        self.selected_text = None # Store text from UI input
        self.selected_device_display_name = None # Just the name part (e.g., 'MyPC')
        self.selected_device_address = None # Store (ip, port) of selected target
        self.is_transfer_active = False
        self.current_transfer_cancel_event = None # Event for the active transfer
        self.current_transfer_address = None # Address tuple of the active transfer peer
        self.pending_confirmations = {} # {addr_str: confirmation_event}
        self.confirmation_results = {} # {addr_str: bool_result}
        self.history_log = [] # Store tuples: (timestamp, type, status, details)

        # Communication & Control
        self.discovery_queue = queue.Queue()
        self.transfer_queue = queue.Queue()
        self.stop_event = threading.Event() # Global shutdown signal

        # Modules
        self.network_discovery = NetworkDiscovery(self.discovery_queue, self.stop_event, self.config)
        # Pass self reference to receiver for confirmation callback
        self.file_receiver = FileReceiver(self.config, self.transfer_queue, self.stop_event, self)

    def set_main_window(self, window):
        self.main_window = window
        # Check downloads dir validity on startup based on config
        downloads_dir = self.config.get_setting('Preferences', 'downloads_directory')
        try:
            # Attempt to create if it doesn't exist? Risky. Better to just check.
            if not Path(downloads_dir).is_dir():
                # Try to get default path again as fallback display
                fallback_path = self.config._defaults['Preferences']['downloads_directory']
                error_msg = (f"Configured downloads directory '{downloads_dir}' is invalid or inaccessible.\n"
                             f"Please check config file or ensure folder exists.\n"
                             f"Using fallback path for checks: {fallback_path}\n"
                             "(File reception may fail if path is unwritable)")
                # Use root.after to ensure messagebox runs in main thread after window is ready
                self.root.after(100, lambda: self.main_window.show_error("Configuration Error", error_msg))
        except Exception as e:
             # Catch errors during path check itself
             error_msg = f"Error checking downloads directory '{downloads_dir}': {e}"
             self.root.after(100, lambda: self.main_window.show_error("Configuration Error", error_msg))


    def start(self):
        """Starts background processes and the update queue polling."""
        print("AppLogic: Starting...")
        self.network_discovery.start()
        self.file_receiver.start() # Receiver now checks downloads dir internally if needed
        self._poll_queues()
        self._update_button_states() # Initial button state update


    def _poll_queues(self):
        """Periodically checks discovery and transfer queues for messages."""
        # --- Process Discovery Queue ---
        try:
            while not self.discovery_queue.empty():
                message = self.discovery_queue.get_nowait()
                action = message[0]

                if not self.main_window: continue # Skip if UI gone

                if action == "status":
                    if not self.is_transfer_active: # Avoid overwriting transfer status
                        status_msg = message[1]
                        self.root.after(0, lambda m=status_msg: self.main_window.update_status(m))
                elif action == "add":
                    # message = ("add", full_service_name, info_obj, os_info)
                    full_service_name, info, os_info = message[1:]
                    # Avoid adding self (check full advertised name)
                    if full_service_name != self.network_discovery.get_advertised_name():
                        self.discovered_services[full_service_name] = (info, os_info)
                        display_name = full_service_name.split(f'.{SERVICE_TYPE}')[0]
                        self.root.after(0, lambda d=display_name, o=os_info: self.main_window.update_device_list("add", d, o))
                elif action == "remove":
                    # message = ("remove", full_service_name)
                    full_service_name = message[1]
                    if full_service_name in self.discovered_services:
                        display_name = full_service_name.split(f'.{SERVICE_TYPE}')[0]
                        del self.discovered_services[full_service_name]
                        self.root.after(0, lambda d=display_name: self.main_window.update_device_list("remove", d))
                        # If removed device was selected, clear selection
                        if self.selected_device_display_name == display_name:
                            self.handle_device_selection(None) # Clear selection via handler

        except queue.Empty: pass
        except Exception as e: print(f"Error processing discovery queue: {e}\n{traceback.format_exc()}")

        # --- Process Transfer Queue ---
        try:
             while not self.transfer_queue.empty():
                message = self.transfer_queue.get_nowait()
                action = message[0]

                if not self.main_window: continue # Skip if UI gone

                # --- Handle Specific Actions ---
                if action == "status":
                    # msg = ('status', message)
                    status_msg = message[1]
                    self.root.after(0, lambda m=status_msg: self.main_window.update_status(m))

                elif action == "progress":
                    # msg = ('progress', 'send'/'receive', current, total, speed, eta)
                    self.is_transfer_active = True # Ensure flag is set
                    _op, current, total, speed, eta = message[1:]
                    self.root.after(0, lambda c=current, t=total, s=speed, e=eta: self.main_window.update_progress(c, t, s, e))
                    # Button states managed by _update_button_states called periodically or on state change
                    self._update_button_states() # Update now to ensure cancel is enabled

                elif action == "complete":
                    # msg = ('complete', 'send'/'receive', success_msg)
                    op_type, success_msg = message[1:]
                    title = "Transfer Complete"
                    # Use standard success box for file, custom logic handles text popup trigger
                    if op_type == "send" or "File" in success_msg: # Check if it's file-related
                        self.root.after(0, lambda t=title, m=success_msg: self.main_window.show_success(t, m))

                    self.root.after(0, lambda m=success_msg: self.main_window.update_status(f"Complete: {m}"))
                    self.root.after(0, self.main_window.reset_progress)
                    self._add_history(op_type, "Success", success_msg)
                    self._reset_transfer_state() # Sets is_transfer_active=False and updates buttons

                elif action == "error":
                    # msg = ('error', 'send'/'receive'/'server'/'cancel', error_msg)
                    op_type, error_msg = message[1], message[2]
                    title = f"{op_type.capitalize()} Error"
                    self.root.after(0, lambda t=title, m=error_msg: self.main_window.show_error(t, m))
                    self.root.after(0, lambda m=error_msg: self.main_window.update_status(f"Error: {m}"))
                    self.root.after(0, self.main_window.reset_progress)
                    # Use specific status if it was a cancellation
                    status = "Cancelled" if op_type == "cancel" else "Failed"
                    self._add_history(op_type, status, error_msg)
                    self._reset_transfer_state()

                elif action == "confirm_receive":
                     # msg = ('confirm_receive', filename, size, addr_str, confirmation_event)
                     filename, size, addr_str, confirmation_event = message[1:]
                     # Check if already confirming for this address to prevent duplicates
                     if addr_str not in self.pending_confirmations:
                         self.pending_confirmations[addr_str] = confirmation_event
                         # Ask user in main thread
                         self.root.after(0, lambda f=filename, s=size, a=addr_str: self._ask_user_confirmation(f, s, a))
                     else:
                          print(f"Ignoring duplicate confirmation request for {addr_str}")

                elif action == "text_received":
                     # msg = ('text_received', text_content, source_addr_str)
                     text_content, source_addr_str = message[1:]
                     # Handle display/copy in main thread
                     self.root.after(0, lambda txt=text_content, src=source_addr_str: self._handle_received_text(txt, src))
                     # Completion/history is handled by the 'complete' message that follows text reception

                elif action == "info": # General info messages for status bar/history
                     info_msg = message[1]
                     self.root.after(0, lambda m=info_msg: self.main_window.update_status(f"Info: {m}"))
                     self._add_history("info", "Info", info_msg)

        except queue.Empty: pass
        except IndexError: print(f"Warning: Malformed message in transfer queue: {message}")
        except Exception as e: print(f"Error processing transfer queue: {e}\n{traceback.format_exc()}")

        finally:
            # Only reschedule if the stop event isn't set
            if not self.stop_event.is_set():
                 self.root.after(150, self._poll_queues) # Reschedule polling

    def _update_button_states(self):
        """Central method to update UI button states based on app state."""
        # Send button enabled if: not active transfer AND device selected AND (file selected OR text entered)
        has_file = bool(self.selected_filepath)
        # Ensure text state is current
        if self.main_window and hasattr(self.main_window, 'text_input'):
             try:
                 current_text = self.main_window.text_input.get("1.0", tk.END).strip()
                 self.selected_text = current_text if current_text else None
             except Exception: # Catch potential errors if widget state is weird
                 self.selected_text = None
        else:
             self.selected_text = None # Ensure it's None if UI not ready

        has_text = bool(self.selected_text)
        can_send = bool(self.selected_device_display_name and (has_file or has_text))

        send_enabled = can_send and not self.is_transfer_active
        cancel_enabled = self.is_transfer_active

        if self.main_window:
             # Schedule UI update in main thread
             self.root.after(0, lambda se=send_enabled, ce=cancel_enabled: self.main_window.update_button_states(se, ce))

    def check_send_button_state_external(self):
        """Allows UI to trigger a button state check, e.g., on text change."""
        # Update internal text state first (already handled in _update_button_states, just trigger it)
        self._update_button_states()

    def _reset_transfer_state(self):
         """Clears flags and events after a transfer finishes, fails or is cancelled."""
         self.is_transfer_active = False
         self.current_transfer_cancel_event = None
         self.current_transfer_address = None
         self._update_button_states() # Update buttons now transfer is done

    def _add_history(self, type, status, details):
        """Adds an entry to the history log and updates UI."""
        timestamp = time.time()
        log_entry = (timestamp, type, status, details)
        self.history_log.append(log_entry)
        # Limit history size? e.g., self.history_log = self.history_log[-100:]
        if self.main_window:
             # Format for display
             details_short = (str(details)[:75] + '...') if len(str(details)) > 75 else str(details)
             log_str = f"[{type[:4].upper()}] {status}: {details_short}" # Shorten type if needed
             self.main_window.add_history_log(log_str)

    def _ask_user_confirmation(self, filename, size_bytes, addr_str):
        """Show confirmation dialog (runs in main thread via root.after)."""
        if not self.main_window:
             print(f"Cannot ask confirmation for {addr_str}, main window is gone.")
             # Automatically reject if UI is gone?
             self.confirmation_results[addr_str] = False
             if addr_str in self.pending_confirmations:
                 self.pending_confirmations[addr_str].set()
                 del self.pending_confirmations[addr_str]
             return

        try:
            size_str = f"{size_bytes / (1024*1024):.2f} MB" if size_bytes >= 1024*1024 else f"{size_bytes / 1024:.1f} KB"
            if size_bytes < 1024: size_str = f"{size_bytes} B"

            title = "Incoming File Transfer"
            message = f"Accept file '{filename}' ({size_str})\nfrom {addr_str}?"

            result = self.main_window.ask_confirmation(title, message) # Executes in main thread
            print(f"User confirmation result for {addr_str}: {result}")

            # Store result and signal waiting receiver thread
            self.confirmation_results[addr_str] = result
            if addr_str in self.pending_confirmations:
                self.pending_confirmations[addr_str].set() # Wake up receiver thread
                del self.pending_confirmations[addr_str] # Clean up
            else:
                 print(f"Warning: Confirmation event not found for {addr_str} after dialog.")
        except Exception as e:
             print(f"Error during user confirmation dialog for {addr_str}: {e}")
             # Default to reject on error
             self.confirmation_results[addr_str] = False
             if addr_str in self.pending_confirmations:
                 self.pending_confirmations[addr_str].set()
                 del self.pending_confirmations[addr_str]

    def get_confirmation_result(self, addr_str) -> bool:
         """Called by receiver thread (via self reference) to get stored result."""
         result = self.confirmation_results.get(addr_str, False) # Default to False (reject)
         # Clean up result after retrieval
         if addr_str in self.confirmation_results:
             del self.confirmation_results[addr_str]
         return result

    def _handle_received_text(self, text_content, source_addr_str):
         """Handle received text snippet using custom popup."""
         print(f"Handling received text from {source_addr_str}")

         # Use the custom method for displaying text
         title = f"Text Snippet from {source_addr_str}"
         # Schedule the popup display in the main thread
         # Ensure main window exists before scheduling
         if self.main_window:
              self.root.after(0, lambda t=title, c=text_content: self.main_window.show_selectable_text_popup(t, c))
         else:
              print("Cannot display received text, main window is not available.")

         # Copy to clipboard (if available and enabled)
         if pyperclip and self.config.get_boolean_setting('Preferences', 'copy_text_to_clipboard'):
             try:
                 pyperclip.copy(text_content)
                 print("Copied received text to clipboard.")
                 if self.main_window: # Update status only if window exists
                      self.root.after(100, lambda: self.main_window.update_status("Text copied to clipboard."))
             except Exception as e:
                  print(f"Failed to copy text to clipboard: {e}")
                  if self.main_window:
                       self.root.after(0, lambda: self.main_window.show_error("Clipboard Error", f"Could not copy text: {e}"))


    # --- Event Handlers (Called by MainWindow) ---

    def handle_file_selection(self, filepath):
        """Processes file selection from the UI."""
        self.selected_filepath = filepath
        # Update internal text state when file selected (clear text)
        self.selected_text = None
        if filepath:
            filename = os.path.basename(filepath)
            if self.main_window and not self.is_transfer_active:
                 self.root.after(0, lambda f=filename: self.main_window.update_status(f"Selected File: {f}"))
        else:
             if self.main_window and not self.is_transfer_active:
                 self.root.after(0, lambda: self.main_window.update_status("File selection cancelled."))
        # Clear UI text input if file is selected
        if self.main_window and hasattr(self.main_window, 'text_input'):
             self.root.after(0, lambda: self.main_window.text_input.delete('1.0', tk.END))

        self._update_button_states()


    def handle_device_selection(self, display_name):
        """Processes device selection from the UI (expects name without OS tag)."""
        self.selected_device_display_name = display_name
        self.selected_device_address = None # Clear address until needed
        # Find the corresponding service info to potentially store address early (optional)
        if display_name:
             full_service_name = f"{display_name}.{SERVICE_TYPE}"
             service_data = self.discovered_services.get(full_service_name)
             if service_data:
                  info, _os = service_data
                  try:
                       if info.parsed_addresses():
                            ip = info.parsed_addresses()[0]
                            port = info.port
                            self.selected_device_address = (ip, port) # Store for potential later use
                  except (IndexError, AttributeError) as e:
                       print(f"Could not get address for selected device {display_name}: {e}")

        self._update_button_states()

    def handle_send_request(self, item_to_send, item_type):
        """Handles the user clicking the 'Send' button."""
        if self.is_transfer_active:
             if self.main_window: self.main_window.show_error("Busy", "Another transfer is already in progress.")
             return
        if not item_to_send:
             if self.main_window: self.main_window.show_error("Send Error", "No file or text specified.")
             return
        if not self.selected_device_display_name:
            if self.main_window: self.main_window.show_error("Send Error", "Please select a target device.")
            return

        # Find target info again to ensure it's current
        target_service_name = f"{self.selected_device_display_name}.{SERVICE_TYPE}"
        service_data = self.discovered_services.get(target_service_name)

        if not service_data:
            msg = f"Device '{self.selected_device_display_name}' may no longer be available."
            if self.main_window: self.main_window.show_error("Send Error", msg)
            self.root.after(0, lambda d=self.selected_device_display_name: self.main_window.update_device_list("remove", d))
            self.handle_device_selection(None) # Clear selection state
            return

        info, _os = service_data
        try:
            if not info.parsed_addresses(): raise ValueError("No parsed addresses.")
            ip_address = info.parsed_addresses()[0]
            port = info.port
            self.selected_device_address = (ip_address, port) # Store current target

            print(f"Logic: Preparing to send {item_type} to {self.selected_device_display_name} at {ip_address}:{port}")
            if self.main_window: self.root.after(0, lambda: self.main_window.update_status(f"Initiating send ({item_type})..."))

            # Create cancellation event for this transfer
            self.current_transfer_cancel_event = threading.Event()
            self.is_transfer_active = True
            self.current_transfer_address = (ip_address, port) # Store target address for cancellation purposes
            self._update_button_states() # Disable send, enable cancel

            # Get TLS settings from config
            use_tls = self.config.get_boolean_setting('Network', 'enable_tls')
            # Client needs context configured for client usage
            ssl_context = None
            if use_tls:
                 # Assuming FileReceiver initialized its context if needed
                 # Create a client-specific context
                 try:
                      # Need cert dir path from config manager or receiver
                      cert_dir = Path(self.config.config_path.parent) / "certs" # Assuming relative to config
                      cert_file = cert_dir / "landrop_cert.pem"
                      key_file = cert_dir / "landrop_key.pem"
                      # Import moved inside try block to avoid top-level import if unused
                      from ..network.transfer import create_ssl_context
                      ssl_context = create_ssl_context(cert_dir, key_file, cert_file, server_side=False)
                      if not ssl_context:
                           print("Warning: Failed to create client SSL context. Sending without TLS.")
                           use_tls = False # Fallback to no TLS if context fails
                 except ImportError:
                      print("Warning: Could not import create_ssl_context. Sending without TLS.")
                      use_tls = False
                 except Exception as e:
                      print(f"Error preparing client TLS context: {e}. Sending without TLS.")
                      use_tls = False


            sender = FileSender(
                host=ip_address,
                port=port,
                item=item_to_send,
                item_type=item_type,
                status_queue=self.transfer_queue,
                cancel_event=self.current_transfer_cancel_event,
                use_tls=use_tls,
                ssl_context=ssl_context # Pass configured context
            )
            send_thread = threading.Thread(target=sender.send, daemon=True)
            send_thread.start()

        except (IndexError, ValueError, AttributeError) as e:
             error_msg = f"Could not get valid connection details for '{self.selected_device_display_name}'. Error: {e}"
             if self.main_window: self.main_window.show_error("Send Error", error_msg)
             self._reset_transfer_state() # Reset state on error
        except Exception as e:
             error_msg = f"An unexpected error occurred preparing the send: {e}"
             if self.main_window: self.main_window.show_error("Send Error", f"{error_msg}\n{traceback.format_exc()}")
             self._reset_transfer_state()


    def handle_cancel_request(self):
         """Handles user clicking the Cancel button."""
         if self.is_transfer_active and self.current_transfer_cancel_event:
              print("Logic: Handling cancel request.")
              # Signal the sender/receiver thread via its specific cancel event
              self.current_transfer_cancel_event.set()
              # Note: If the active transfer is *incoming*, we need to tell the
              # FileReceiver instance to cancel the specific handler thread.
              # This current logic primarily cancels outgoing transfers.
              # A more robust solution might involve storing if the active transfer
              # is incoming or outgoing. For now, sender cancellation is primary.

              # Update UI immediately
              if self.main_window: self.root.after(0, lambda: self.main_window.update_status("Cancelling transfer..."))
              # The transfer thread will eventually send an 'error' status with cancellation details
              # which will call _reset_transfer_state and update buttons finally.
              # Set is_transfer_active false early? Risky, let the thread confirm cancellation.
         else:
              print("Logic: Cancel requested but no active transfer or event.")

    def handle_shutdown(self):
        """Initiates the application shutdown sequence."""
        if self.stop_event.is_set(): return # Avoid running shutdown twice
        print("AppLogic: Handling shutdown request...")
        self.stop_event.set() # Signal all main loops FIRST

        if self.main_window:
             # Use root.after to ensure UI updates happen before threads might be fully stopped
             self.root.after(0, lambda: self.main_window.update_button_states(send_enabled=False, cancel_enabled=False))
             self.root.after(0, lambda: self.main_window.update_status("Shutting down..."))

        # Ask components to shut down
        self.network_discovery.shutdown()
        self.file_receiver.shutdown() # This now also signals active transfers to cancel

        print("AppLogic: Scheduling UI destruction.")
        # Increased delay to allow threads more time to attempt cleanup
        self.root.after(700, self._destroy_ui) # Longer delay

    def _destroy_ui(self):
        """Safely destroys the main UI window."""
        print("AppLogic: Attempting to destroy UI.")
        if self.main_window:
            try:
                # Check if root exists and is valid window before destroying
                if self.root and self.root.winfo_exists():
                    self.main_window.destroy_window()
                else:
                     print("AppLogic: UI window already destroyed or invalid.")
            except Exception as e:
                print(f"Error destroying window during shutdown: {e}")
        print("AppLogic: UI destruction attempt finished.")