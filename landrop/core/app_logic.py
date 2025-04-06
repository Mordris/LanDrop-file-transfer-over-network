import tkinter as tk
import queue
import threading
import os
import sys
from pathlib import Path
import time
import traceback

# Attempt to import pyperclip for clipboard functionality
try:
    import pyperclip
except ImportError:
    pyperclip = None
    # Warning printed during initialization if needed
    # print("Warning: 'pyperclip' not installed. Text copy features disabled.")

# Relative imports of project modules
from ..network.discovery import NetworkDiscovery
from ..network.transfer import FileSender, FileReceiver, create_ssl_context # Import network classes and SSL helper
from ..utils.file_utils import generate_unique_filepath # Import specific util
from ..utils.config_manager import ConfigManager
from ..utils.constants import (SERVICE_TYPE, APP_PORT, APP_NAME, CERT_DIR_NAME,
                        CERT_FILE_NAME, KEY_FILE_NAME,
                        TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                        TRANSFER_TYPE_MULTI_START) # Import constants
# For resolving IP addresses
from zeroconf import IPVersion


class AppLogic:
    """
    Coordinates UI (MainWindow), network discovery (NetworkDiscovery),
    file transfers (FileSender, FileReceiver), history logging,
    configuration management (ConfigManager), and application state.
    """
    def __init__(self, root: tk.Tk, config: ConfigManager):
        """
        Initializes the application logic.

        Args:
            root: The Tkinter root window instance.
            config: The initialized ConfigManager instance.
        """
        self.root = root
        self.config = config
        self.main_window = None # Reference to MainWindow instance, set via set_main_window

        # --- State Variables ---
        # Discovery State
        self.discovered_services = {} # {full_service_name: (info_obj, os_info)}
        self.selected_device_display_name = None # User-friendly name of the target device
        self.selected_device_address = None # Resolved (ip, port) tuple of the target

        # Selection State (What to send)
        self.selected_filepaths = [] # List of absolute paths for multi-file selection
        self.selected_folderpath = None # Absolute path for folder selection
        self.selected_text = None # Text snippet if it's the active selection

        # Transfer State
        self.is_transfer_active = False # Flag indicating if a send/receive is in progress
        self.current_transfer_cancel_event = None # Event to signal cancellation to the active transfer thread
        self.current_transfer_address = None # (ip, port) of the peer in the active transfer
        self.current_transfer_is_multi = False # Flag if the active transfer is a multi-file batch

        # Confirmation State (Managed here for thread safety via queues/events)
        # Stores events that receiver threads wait on for UI confirmation
        self.pending_confirmations = {} # {addr_str: confirmation_event}
        # Stores the boolean result from the UI confirmation dialog
        self.confirmation_results = {} # {addr_str: bool_result}

        # History Log
        self.history_log = [] # List of tuples: (timestamp, type, status, details)

        # --- Communication & Control ---
        self.discovery_queue = queue.Queue() # Messages from NetworkDiscovery thread
        self.transfer_queue = queue.Queue() # Status messages from FileSender/FileReceiver threads
        self.stop_event = threading.Event() # Global shutdown signal for all threads

        # --- Modules Initialization ---
        self.network_discovery = NetworkDiscovery(self.discovery_queue, self.stop_event, self.config)
        # Pass self reference to receiver for callbacks (confirmation result retrieval)
        self.file_receiver = FileReceiver(self.config, self.transfer_queue, self.stop_event, self)

        # Print warning if pyperclip is missing (only once)
        if pyperclip is None:
            print("Warning: 'pyperclip' module not installed. Text copy features will be disabled.")
            print("         Install it using: pip install pyperclip")


    def set_main_window(self, window):
        """
        Stores a reference to the main UI window after it's created
        and performs initial UI-dependent checks.

        Args:
            window: The MainWindow instance.
        """
        self.main_window = window
        # Check downloads directory validity now that the UI exists for error reporting
        self._check_downloads_directory()

    def _check_downloads_directory(self):
        """Checks if the configured downloads directory is valid."""
        downloads_dir = self.config.get_setting('Preferences', 'downloads_directory')
        if not downloads_dir:
            print("Error: Downloads directory not found in configuration.")
            return # Cannot proceed without a setting

        try:
            download_path = Path(downloads_dir)
            # Check if it exists and is a directory
            if not download_path.is_dir():
                fallback_path = self.config._defaults['Preferences']['downloads_directory']
                error_msg = (f"Configured downloads directory:\n'{downloads_dir}'\n"
                             f"is invalid or inaccessible.\n\n"
                             f"Using fallback path:\n{fallback_path}\n\n"
                             "(File reception may fail if this path is also invalid or unwritable)")
                # Schedule error display in main thread
                if self.main_window:
                    self.root.after(100, lambda: self.main_window.show_error("Configuration Error", error_msg))
                else:
                    print(f"ERROR: {error_msg}") # Print if UI not ready
        except Exception as e:
             # Catch errors during the path check itself (e.g., permissions)
             error_msg = f"Error checking downloads directory '{downloads_dir}': {e}"
             if self.main_window:
                  self.root.after(100, lambda: self.main_window.show_error("Configuration Error", error_msg))
             else:
                  print(f"ERROR: {error_msg}")


    def start(self):
        """Starts background processes (discovery, receiver) and the queue polling loop."""
        print("AppLogic: Starting background services...")
        self.network_discovery.start()
        self.file_receiver.start()
        # Start polling queues for updates from background threads
        self._poll_queues()
        # Set initial button states based on default state
        self._update_button_states()


    def _poll_queues(self):
        """
        Periodically checks discovery and transfer queues for messages
        from background threads and updates state/UI accordingly.
        This runs continuously via `root.after`.
        """
        # --- Process Discovery Queue ---
        try:
            while not self.discovery_queue.empty():
                message = self.discovery_queue.get_nowait()
                action = message[0]
                # Ensure UI window still exists before trying to update it
                if not self.main_window or not self.root.winfo_exists(): continue

                if action == "status":
                    # Update status bar only if no transfer is active (avoid overwriting progress)
                    if not self.is_transfer_active:
                        status_msg = message[1]
                        self.root.after(0, lambda m=status_msg: self.main_window.update_status(m))
                elif action == "add":
                    # ('add', full_service_name, zeroconf_info_obj, os_info_str)
                    full_service_name, info, os_info = message[1:]
                    # Avoid adding self by comparing advertised name
                    if full_service_name != self.network_discovery.get_advertised_name():
                        self.discovered_services[full_service_name] = (info, os_info)
                        # Extract display name (part before ._landrop._tcp.local.)
                        display_name = full_service_name.split(f'.{SERVICE_TYPE}')[0]
                        # Schedule UI update in main thread
                        self.root.after(0, lambda d=display_name, o=os_info: self.main_window.update_device_list("add", d, o))
                elif action == "remove":
                    # ('remove', full_service_name)
                    full_service_name = message[1]
                    if full_service_name in self.discovered_services:
                        display_name = full_service_name.split(f'.{SERVICE_TYPE}')[0]
                        del self.discovered_services[full_service_name]
                        # Schedule UI update
                        self.root.after(0, lambda d=display_name: self.main_window.update_device_list("remove", d))
                        # If the removed device was the selected one, clear the selection
                        if self.selected_device_display_name == display_name:
                            self.handle_device_selection(None) # Clear selection state

        except queue.Empty: pass # No discovery messages, normal
        except Exception as e: print(f"Error processing discovery queue: {e}\n{traceback.format_exc()}")

        # --- Process Transfer Queue ---
        try:
             while not self.transfer_queue.empty():
                message = self.transfer_queue.get_nowait()
                action = message[0]
                if not self.main_window or not self.root.winfo_exists(): continue

                # --- Handle Specific Actions from Transfer Agents ---
                if action == "status":
                    # ('status', message_string)
                    self.root.after(0, lambda m=message[1]: self.main_window.update_status(m))

                elif action == "progress":
                    # ('progress', 'send'/'receive', current_bytes, total_bytes, speed_bps, eta_sec, context_msg)
                    self.is_transfer_active = True # Ensure flag is set during progress
                    _op, current, total, speed, eta, context = message[1:]
                    self.root.after(0, lambda c=current, t=total, s=speed, e=eta, ctx=context: self.main_window.update_progress(c, t, s, e, ctx))
                    # No need to call _update_button_states here; transfer active state handles it

                elif action == "complete":
                    # ('complete', 'send'/'receive', success_message)
                    op_type, success_msg = message[1:]
                    title = "Transfer Complete"
                    # Show success popup only for file/batch transfers, not text
                    is_text_related = "text snippet" in success_msg.lower()
                    if not is_text_related:
                        self.root.after(0, lambda t=title, m=success_msg: self.main_window.show_success(t, m))

                    self.root.after(0, lambda m=success_msg: self.main_window.update_status(f"Complete: {m}"))
                    self.root.after(0, self.main_window.reset_progress) # Reset progress bar
                    self._add_history(op_type, "Success", success_msg)
                    self._reset_transfer_state() # Reset flags and update buttons

                elif action == "error":
                    # ('error', 'send'/'receive'/'server'/'cancel', error_message)
                    op_type, error_msg = message[1], message[2]
                    title = f"{op_type.capitalize()} Error"
                    self.root.after(0, lambda t=title, m=error_msg: self.main_window.show_error(t, m))
                    self.root.after(0, lambda m=error_msg: self.main_window.update_status(f"Error: {m}"))
                    self.root.after(0, self.main_window.reset_progress)
                    status = "Cancelled" if op_type == "cancel" else "Failed"
                    self._add_history(op_type, status, error_msg)
                    self._reset_transfer_state() # Reset flags and update buttons

                elif action == "confirm_receive":
                     # ('confirm_receive', item_name, size_bytes, addr_str, confirmation_event, is_multi, item_count)
                     item_name, size, addr_str, confirmation_event = message[1:5]
                     is_multi = message[5] if len(message) > 5 else False
                     item_count = message[6] if len(message) > 6 else 1

                     if addr_str not in self.pending_confirmations:
                         self.pending_confirmations[addr_str] = confirmation_event
                         # Schedule the UI dialog in the main thread
                         self.root.after(0, lambda name=item_name, s=size, a=addr_str, multi=is_multi, count=item_count:
                                         self._ask_user_confirmation(name, s, a, multi, count))
                     else: print(f"Ignoring duplicate confirmation request for {addr_str}")

                elif action == "text_received":
                     # ('text_received', text_content, source_addr_str)
                     text_content, source_addr_str = message[1:]
                     self.root.after(0, lambda txt=text_content, src=source_addr_str: self._handle_received_text(txt, src))

                elif action == "info":
                     # ('info', info_message) - General info for status or history
                     info_msg = message[1]
                     self.root.after(0, lambda m=info_msg: self.main_window.update_status(f"Info: {m}"))
                     self._add_history("info", "Info", info_msg)

        except queue.Empty: pass # Normal case
        except IndexError as e: print(f"Warning: Malformed message in transfer queue: {message} - {e}")
        except Exception as e: print(f"Error processing transfer queue: {e}\n{traceback.format_exc()}")

        finally:
            # Reschedule polling if application is not shutting down
            if not self.stop_event.is_set():
                 self.root.after(150, self._poll_queues) # Poll every 150ms

    def _update_button_states(self):
        """Central method to update UI button states based on current app state."""
        try:
            # Determine if there's something selected to send
            has_files = bool(self.selected_filepaths)
            has_folder = bool(self.selected_folderpath)
            has_text = False # Check text only if files/folder are NOT selected

            if not has_files and not has_folder:
                if self.main_window and hasattr(self.main_window, 'text_input'):
                    current_text = self.main_window.text_input.get("1.0", tk.END).strip()
                    has_text = bool(current_text)
                    # Update internal state only if text is the active selection
                    self.selected_text = current_text if has_text else None
                else: self.selected_text = None # Clear if UI not ready
            else: self.selected_text = None # Clear text state if files/folder active

            can_select_item = has_files or has_folder or has_text
            can_select_target = bool(self.selected_device_display_name)
            can_send = can_select_item and can_select_target

            # Determine button enable/disable states
            send_enabled = can_send and not self.is_transfer_active
            cancel_enabled = self.is_transfer_active

            # Schedule UI update in main thread if window exists
            if self.main_window and self.root.winfo_exists():
                 self.root.after(0, lambda se=send_enabled, ce=cancel_enabled: self.main_window.update_button_states(se, ce))
        except tk.TclError: pass # Ignore errors if UI is being destroyed
        except Exception as e: print(f"Error updating button states: {e}")

    def check_send_button_state_external(self):
        """Allows UI to trigger a button state check externally (e.g., on text change)."""
        self._update_button_states()

    def _reset_transfer_state(self):
         """Clears transfer-related flags and updates UI buttons."""
         print("AppLogic: Resetting transfer state.")
         self.is_transfer_active = False
         self.current_transfer_cancel_event = None
         self.current_transfer_address = None
         self.current_transfer_is_multi = False
         # Update buttons immediately after resetting state
         self._update_button_states()

    def _add_history(self, type, status, details):
        """Adds an entry to the history log and schedules UI update."""
        timestamp = time.time()
        log_entry = (timestamp, type, status, details)
        self.history_log.append(log_entry)
        # Limit history size? e.g., self.history_log = self.history_log[-100:]
        if self.main_window and self.root.winfo_exists():
             details_short = (str(details)[:75] + '...') if len(str(details)) > 75 else str(details)
             type_short = type[:4].upper() if len(type) > 4 else type.upper()
             log_str = f"[{type_short}] {status}: {details_short}"
             # MainWindow's method already uses root.after
             self.main_window.add_history_log(log_str)

    def _ask_user_confirmation(self, item_name, size_bytes, addr_str, is_multi=False, item_count=1):
        """Displays confirmation dialog (must run in main thread)."""
        if not self.main_window or not self.root.winfo_exists():
             print(f"Cannot ask confirmation for {addr_str}, main window gone.")
             self.confirmation_results[addr_str] = False # Auto-reject
             if addr_str in self.pending_confirmations:
                 try: self.pending_confirmations[addr_str].set()
                 except Exception: pass
                 del self.pending_confirmations[addr_str]
             return

        result = False # Default to reject
        try:
            size_str = self.main_window._format_size(size_bytes) if hasattr(self.main_window, '_format_size') else f"{size_bytes} B"
            title = "Incoming Batch Transfer" if is_multi else "Incoming File Transfer"
            message = (f"Accept {item_count} items ({size_str})\nin batch '{item_name}' from {addr_str}?"
                       if is_multi else
                       f"Accept file '{item_name}' ({size_str})\nfrom {addr_str}?")

            # This executes in main thread because it was scheduled via root.after
            result = self.main_window.ask_confirmation(title, message)
            print(f"User confirmation result for {addr_str}: {result}")

        except Exception as e:
             print(f"Error during user confirmation dialog for {addr_str}: {e}")
             result = False # Ensure rejection on error
        finally:
            # Store result and signal waiting receiver thread regardless of dialog success/failure
            self.confirmation_results[addr_str] = result
            if addr_str in self.pending_confirmations:
                try:
                    self.pending_confirmations[addr_str].set() # Signal waiter
                except Exception as set_e:
                    print(f"Error setting confirmation event for {addr_str}: {set_e}")
                # Remove from pending list *after* setting the event
                del self.pending_confirmations[addr_str]
            else:
                 # Event might be gone if receiver timed out/errored before dialog finished
                 print(f"Warning: Confirmation event no longer pending for {addr_str} after dialog.")
                 # Clean up result dict if event gone
                 if addr_str in self.confirmation_results: del self.confirmation_results[addr_str]

    def get_confirmation_result(self, addr_str) -> bool:
         """Called by receiver thread to retrieve the stored confirmation result."""
         # Receiver's finally block should clean up the result dict entry
         return self.confirmation_results.get(addr_str, False)

    def _handle_received_text(self, text_content, source_addr_str):
         """Displays received text popup and handles clipboard copy."""
         print(f"Handling received text from {source_addr_str}")
         title = f"Text Snippet from {source_addr_str}"

         # Schedule UI popup in main thread
         if self.main_window and self.root.winfo_exists():
              self.root.after(0, lambda t=title, c=text_content: self.main_window.show_selectable_text_popup(t, c))
         else: print("Cannot display received text, main window is not available.")

         # Copy to clipboard if enabled
         if pyperclip and self.config.get_boolean_setting('Preferences', 'copy_text_to_clipboard'):
             try:
                 pyperclip.copy(text_content)
                 print("Copied received text to clipboard.")
                 if self.main_window and self.root.winfo_exists():
                      self.root.after(100, lambda: self.main_window.update_status("Text copied to clipboard."))
             except Exception as e:
                  print(f"Failed to copy text to clipboard: {e}")
                  if self.main_window and self.root.winfo_exists():
                       self.root.after(0, lambda: self.main_window.show_error("Clipboard Error", f"Could not copy text: {e}"))


    # --- Event Handlers (Called by MainWindow) ---

    def handle_files_selection(self, filepaths: list | tuple | None):
        """Processes multiple file selections from UI. Clears other selections."""
        new_selection = list(filepaths) if filepaths else []
        if new_selection != self.selected_filepaths:
            self.selected_filepaths = new_selection
            self.selected_folderpath = None # Clear folder
            self.selected_text = None # Clear text state
            print(f"AppLogic: Files selected: {len(self.selected_filepaths)}")
            # UI display update is handled by MainWindow callback (_select_files_ui)
            # Clear UI text input if files selected
            if self.main_window and hasattr(self.main_window, 'text_input'):
                self.root.after(0, lambda: self.main_window.text_input.delete('1.0', tk.END))
            self._update_button_states() # Update buttons based on new state

    def handle_folder_selection(self, folderpath: str | None):
        """Processes folder selection from UI. Clears other selections."""
        if folderpath != self.selected_folderpath:
            self.selected_folderpath = folderpath
            self.selected_filepaths = [] # Clear files
            self.selected_text = None # Clear text state
            print(f"AppLogic: Folder selected: {self.selected_folderpath}")
            # UI display update is handled by MainWindow callback (_select_folder_ui)
            # Clear UI text input if folder selected
            if self.main_window and hasattr(self.main_window, 'text_input'):
                self.root.after(0, lambda: self.main_window.text_input.delete('1.0', tk.END))
            self._update_button_states() # Update buttons based on new state

    def handle_device_selection(self, display_name):
        """Processes device selection from the UI listbox."""
        if display_name != self.selected_device_display_name:
            self.selected_device_display_name = display_name
            self.selected_device_address = None # Reset address
            print(f"AppLogic: Device selected: {display_name}")
            # Try to resolve address immediately
            if display_name:
                 full_service_name = f"{display_name}.{SERVICE_TYPE}"
                 service_data = self.discovered_services.get(full_service_name)
                 if service_data:
                      info, _ = service_data
                      try:
                           addrs = info.parsed_addresses(IPVersion.V4Only) # Prefer IPv4
                           if addrs: self.selected_device_address = (addrs[0], info.port); print(f"   Resolved address: {self.selected_device_address}")
                           else: print("   Warning: No IPv4 addresses found for selected device.")
                      except Exception as e: print(f"   Warning: Could not get address for {display_name}: {e}")
                 else: print("   Warning: Service info not found for selected device name.")
            self._update_button_states() # Update buttons as target changed

    def handle_send_request(self, item_to_send, item_type):
        """Handles the 'Send' button click: validates, prepares, starts sender thread."""
        # 1. Check state validity
        if self.is_transfer_active:
             if self.main_window: self.main_window.show_error("Busy", "Another transfer is in progress.")
             return
        if not item_to_send:
             if self.main_window: self.main_window.show_error("Send Error", "Nothing selected to send.")
             return
        if not self.selected_device_display_name:
            if self.main_window: self.main_window.show_error("Send Error", "No target device selected.")
            return

        # 2. Get Target Address (re-resolve for freshness)
        ip_address, port = None, None
        target_service_name = f"{self.selected_device_display_name}.{SERVICE_TYPE}"
        service_data = self.discovered_services.get(target_service_name)
        if service_data:
            info, _ = service_data
            try:
                addrs = info.parsed_addresses(IPVersion.V4Only)
                if not addrs: raise ValueError("No IPv4 addresses.")
                ip_address, port = addrs[0], info.port
                self.selected_device_address = (ip_address, port) # Update stored address
            except Exception as e:
                 if self.main_window: self.main_window.show_error("Send Error", f"Could not resolve address for '{self.selected_device_display_name}': {e}")
                 return
        else:
            if self.main_window: self.main_window.show_error("Send Error", f"Device '{self.selected_device_display_name}' no longer available.")
            self.root.after(0, lambda d=self.selected_device_display_name: self.main_window.update_device_list("remove", d))
            self.handle_device_selection(None)
            return

        # 3. Prepare Transfer State
        self.current_transfer_cancel_event = threading.Event()
        self.is_transfer_active = True
        self.current_transfer_address = (ip_address, port)
        self.current_transfer_is_multi = (item_type == TRANSFER_TYPE_MULTI_START)
        self._update_button_states() # Disable Send, Enable Cancel

        # 4. Prepare TLS Context
        use_tls = self.config.get_boolean_setting('Network', 'enable_tls')
        ssl_context = None
        if use_tls:
             try:
                  cert_dir = Path(self.config.config_path.parent) / CERT_DIR_NAME
                  cert_file = cert_dir / CERT_FILE_NAME; key_file = cert_dir / KEY_FILE_NAME
                  ssl_context = create_ssl_context(cert_dir, key_file, cert_file, server_side=False)
                  if not ssl_context: use_tls = False; print("Warning: Failed client SSL context. Sending unencrypted.")
             except Exception as e: use_tls = False; print(f"Error preparing client TLS: {e}. Sending unencrypted.")

        # 5. Prepare and Start Sender Thread
        send_thread = None
        try:
            sender_args = {
                'host': ip_address, 'port': port, 'status_queue': self.transfer_queue,
                'cancel_event': self.current_transfer_cancel_event,
                'use_tls': use_tls, 'ssl_context': ssl_context, 'item_type': item_type
            }

            if item_type == TRANSFER_TYPE_TEXT:
                print(f"Logic: Preparing TEXT send to {ip_address}:{port}")
                sender_args['item'] = item_to_send
                if self.main_window: self.root.after(0, lambda: self.main_window.update_status("Initiating text send..."))
            elif item_type == TRANSFER_TYPE_FILE:
                print(f"Logic: Preparing SINGLE FILE send to {ip_address}:{port}")
                sender_args['item'] = item_to_send
                if self.main_window: self.root.after(0, lambda item=item_to_send: self.main_window.update_status(f"Initiating send for {os.path.basename(item)}..."))
            elif item_type == TRANSFER_TYPE_MULTI_START:
                print(f"Logic: Preparing MULTI item send to {ip_address}:{port}")
                file_list_info = self._prepare_multi_file_list(item_to_send)
                if not file_list_info: raise ValueError("Failed to prepare file list.")
                sender_args.update({
                    'file_list': file_list_info['files'], 'total_items': file_list_info['count'],
                    'total_size': file_list_info['size'], 'base_name': file_list_info['base_name']
                })
                if self.main_window: self.root.after(0, lambda c=file_list_info['count']: self.main_window.update_status(f"Initiating batch send ({c} items)..."))
            else: raise ValueError(f"Internal Error: Unsupported item_type: {item_type}")

            # Start thread
            sender = FileSender(**sender_args)
            send_thread = threading.Thread(target=sender.send, name="SenderThread", daemon=True)
            send_thread.start()
            print(f"Sender thread started for {item_type} to {ip_address}:{port}")

        # Handle errors *during preparation* only (before thread starts)
        except (ValueError, OSError, Exception) as e:
             error_msg = f"Error preparing send: {e}"
             print(f"ERROR: {error_msg}" + (f"\n{traceback.format_exc()}" if not isinstance(e, ValueError) else ""))
             if self.main_window: self.main_window.show_error("Send Error", error_msg)
             # Reset state because the thread never started
             self._reset_transfer_state()

        # State reset for errors *during* transfer happens via queue processing

    def _prepare_multi_file_list(self, selection) -> dict | None:
        """Walks folder or processes file list to get details for MULTI transfer."""
        files_to_send = [] # List of (absolute_path_str, relative_path_str)
        total_size = 0
        base_name = "Multiple Files" # Default base name

        try:
            if isinstance(selection, str) and os.path.isdir(selection): # Folder path
                folder_path = Path(selection).resolve()
                base_name = folder_path.name
                print(f"Preparing folder: {folder_path}")
                if not os.access(str(folder_path), os.R_OK): raise OSError(f"Permission denied: {folder_path}")

                for root, dirs, files in os.walk(folder_path, topdown=True):
                    # Modify dirs in-place to skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    current_root = Path(root)
                    relative_dir = current_root.relative_to(folder_path)

                    for file in files:
                        if file.startswith('.'): continue # Skip hidden files
                        abs_path = current_root / file
                        try:
                            if abs_path.is_file() and os.access(str(abs_path), os.R_OK):
                                file_size = abs_path.stat().st_size
                                relative_path = relative_dir / file # Keep original structure
                                files_to_send.append((str(abs_path), str(relative_path.as_posix())))
                                total_size += file_size
                            # else: print(f"Debug: Skipping non-file/unreadable: {abs_path}")
                        except OSError as e: print(f"Warning: Cannot access/stat {abs_path}, skipping: {e}")
                        except Exception as e: print(f"Warning: Error processing {abs_path}, skipping: {e}")

            elif isinstance(selection, (list, tuple)): # List/tuple of file paths
                print(f"Preparing {len(selection)} files.")
                base_name = f"{len(selection)} File{'s' if len(selection) != 1 else ''}"
                for file_path_str in selection:
                    file_path = Path(file_path_str).resolve()
                    try:
                        if file_path.is_file() and os.access(str(file_path), os.R_OK):
                            file_size = file_path.stat().st_size
                            # Use filename as relative path for directly selected files
                            files_to_send.append((str(file_path), file_path.name))
                            total_size += file_size
                        else: print(f"Warning: Skipping item (not a readable file): {file_path}")
                    except OSError as e: print(f"Warning: Cannot access/stat {file_path}, skipping: {e}")
                    except Exception as e: print(f"Warning: Error processing {file_path}, skipping: {e}")
            else: # Should not happen with UI logic
                raise TypeError(f"Invalid selection type for multi-transfer: {type(selection)}")

            if not files_to_send: # Check if any valid files were found
                print("Warning: No valid, readable files found in the selection.")
                if self.main_window: self.main_window.show_error("Send Error", "No valid/readable files found in selection.")
                return None

            return {'files': files_to_send, 'count': len(files_to_send), 'size': total_size, 'base_name': base_name}

        except Exception as e: # Catch errors during preparation (permissions, etc.)
             print(f"Error preparing file list: {e}")
             traceback.print_exc()
             if self.main_window: self.main_window.show_error("Preparation Error", f"Could not prepare file list: {e}")
             return None


    def handle_cancel_request(self):
         """Signals the active transfer thread to cancel."""
         if self.is_transfer_active and self.current_transfer_cancel_event:
              print("Logic: Handling cancel request.")
              self.current_transfer_cancel_event.set()
              if self.main_window: self.root.after(0, lambda: self.main_window.update_status("Cancelling transfer..."))
         else: print("Logic: Cancel requested but no active transfer found.")


    def handle_shutdown(self):
        """Initiates the application shutdown sequence."""
        if self.stop_event.is_set(): return # Already shutting down
        print("AppLogic: Handling shutdown request...")
        self.stop_event.set() # Signal all threads

        # Update UI
        if self.main_window and self.root.winfo_exists():
             try:
                 self.root.after(0, lambda: self.main_window.update_button_states(False, False))
                 self.root.after(0, lambda: self.main_window.update_status("Shutting down..."))
             except tk.TclError: pass # Ignore if UI already gone

        # Ask components to stop
        print("AppLogic: Shutting down network discovery...")
        self.network_discovery.shutdown()
        print("AppLogic: Shutting down file receiver...")
        self.file_receiver.shutdown()

        # Schedule final UI destruction
        print("AppLogic: Scheduling UI destruction.")
        self.root.after(750, self._destroy_ui)

    def _destroy_ui(self):
        """Safely destroys the main UI window."""
        print("AppLogic: Attempting to destroy UI...")
        if self.main_window and self.root and self.root.winfo_exists():
            try: self.main_window.destroy_window()
            except Exception as e: print(f"Error destroying window: {e}")
        else: print("AppLogic: UI window already destroyed or invalid.")
        print("AppLogic: UI destruction sequence finished.")