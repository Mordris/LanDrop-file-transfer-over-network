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
    # Optional: print a warning here too, though AppLogic already does
    # print("Warning (UI): 'pyperclip' not installed. Copy button in popup will be disabled.")

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
        self.controller = controller
        self.root.title("LanDrop")
        # Adjusted size for new buttons/label
        self.root.geometry("550x600")
        self.root.minsize(450, 500)

        # --- Styling ---
        style = ttk.Style(self.root)
        try:
            # Prefer themes that generally look better cross-platform
            themes = style.theme_names()
            if 'clam' in themes: style.theme_use('clam')
            elif 'vista' in themes: style.theme_use('vista') # Good on Windows
            elif 'aqua' in themes: style.theme_use('aqua') # Good on macOS
        except tk.TclError:
            print("Could not set a preferred theme, using default.")

        # --- Paned Window for Resizable Sections ---
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned_window.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        # --- Top Frame (Discovery & Actions) ---
        self.top_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(self.top_frame, weight=3) # Give more initial space

        # Configure grid weights for resizing
        self.top_frame.rowconfigure(1, weight=1) # Listbox row expands
        self.top_frame.columnconfigure(0, weight=1) # Listbox column expands
        self.top_frame.columnconfigure(1, weight=0) # Text input column fixed initially

        # Device Discovery List
        devices_label = ttk.Label(self.top_frame, text="Discovered Devices:")
        devices_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 2))

        listbox_frame = ttk.Frame(self.top_frame)
        listbox_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        listbox_frame.rowconfigure(0, weight=1)
        listbox_frame.columnconfigure(0, weight=1)
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.devices_listbox = tk.Listbox(
            listbox_frame,
            height=8, # Adjust height as needed
            yscrollcommand=scrollbar.set,
            exportselection=False # Prevents selection clearing on focus loss
        )
        scrollbar.config(command=self.devices_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.devices_listbox.grid(row=0, column=0, sticky="nsew")
        self.devices_listbox.bind('<<ListboxSelect>>', self._on_device_select_ui)

        # Text Input Area
        text_input_frame = ttk.LabelFrame(self.top_frame, text="Text Snippet", padding=5)
        text_input_frame.grid(row=1, column=1, sticky="nsew", pady=(0,0)) # Expand vertically
        text_input_frame.rowconfigure(0, weight=1)
        text_input_frame.columnconfigure(0, weight=1)

        self.text_input = scrolledtext.ScrolledText(
            text_input_frame, height=5, width=25, wrap=tk.WORD
        )
        self.text_input.grid(row=0, column=0, sticky="nsew")
        # Update state when text changes
        self.text_input.bind("<KeyRelease>", self._on_text_change)

        # Selection Status Label (Shows what's selected: files, folder, or text)
        self.selection_label = ttk.Label(self.top_frame, text="Nothing selected", wraplength=300) # Wraps long paths
        self.selection_label.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 2))

        # Action Buttons Frame (File/Folder/Text Send/Cancel)
        action_frame = ttk.Frame(self.top_frame)
        # Place below the selection label
        action_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 0))

        # --- Selection Buttons ---
        self.select_files_button = ttk.Button(
            action_frame, text="Select Files...", command=self._select_files_ui
        )
        self.select_files_button.pack(side=tk.LEFT, padx=(0, 5))

        self.select_folder_button = ttk.Button(
            action_frame, text="Select Folder...", command=self._select_folder_ui
        )
        self.select_folder_button.pack(side=tk.LEFT, padx=(0, 5))

        # --- Send/Cancel Buttons ---
        self.send_button = ttk.Button(
            action_frame, text="Send ->", command=self._send_data_ui,
            state=tk.DISABLED # Initially disabled
        )
        self.send_button.pack(side=tk.LEFT, padx=(0, 5))

        self.cancel_button = ttk.Button(
            action_frame, text="Cancel", command=self._cancel_transfer_ui,
            state=tk.DISABLED # Enabled only during transfer
        )
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 5))

        # Progress Bar
        self.progress_bar = ttk.Progressbar(
            self.top_frame, orient=tk.HORIZONTAL, length=100, mode='determinate'
        )
        # Place below action buttons
        self.progress_bar.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(5, 5))
        self.progress_bar['value'] = 0

        # --- Bottom Frame (History) ---
        self.bottom_frame = ttk.LabelFrame(self.paned_window, text="History", padding=5)
        self.paned_window.add(self.bottom_frame, weight=1) # Less initial space

        self.bottom_frame.rowconfigure(0, weight=1)
        self.bottom_frame.columnconfigure(0, weight=1)

        self.history_text = scrolledtext.ScrolledText(
            self.bottom_frame, height=6, width=60, wrap=tk.WORD, state=tk.DISABLED
        )
        self.history_text.grid(row=0, column=0, sticky="nsew")

        # --- Status Bar (outside PanedWindow) ---
        self.status_label = ttk.Label(
            self.root, text="Status: Initializing...",
            relief=tk.SUNKEN, anchor=tk.W, padding="2 5"
        )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Store last explicit selection type ('files', 'folder', 'text')
        # Used to help determine intent if multiple things *could* be selected
        self.last_explicit_selection_type = None

        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close_request)

    # --- Helper Methods for Formatting ---
    def _format_speed(self, bytes_per_second):
        if bytes_per_second < 1024: return f"{bytes_per_second:.1f} B/s"
        elif bytes_per_second < 1024**2: return f"{bytes_per_second/1024:.1f} KB/s"
        elif bytes_per_second < 1024**3: return f"{bytes_per_second/1024**2:.1f} MB/s"
        else: return f"{bytes_per_second/1024**3:.1f} GB/s"

    def _format_eta(self, seconds):
        if seconds < 0 or seconds > 3600 * 24 * 7: # Avoid nonsensical ETAs (e.g., > 1 week)
            return "--:--"
        try:
            (mins, secs) = divmod(int(seconds), 60)
            (hours, mins) = divmod(mins, 60)
            if hours > 0: return f"{hours:d}:{mins:02d}:{secs:02d}"
            else: return f"{mins:02d}:{secs:02d}"
        except Exception: return "--:--" # Catch potential math errors

    def _format_size(self, size_bytes):
        if size_bytes < 1024: return f"{size_bytes} B"
        elif size_bytes < 1024**2: return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3: return f"{size_bytes/1024**2:.2f} MB"
        else: return f"{size_bytes/1024**3:.2f} GB"

    # --- Private UI Event Handlers ---
    def _select_files_ui(self):
        """Handles 'Select Files...' button click."""
        filepaths = filedialog.askopenfilenames(title="Select Files to Send")
        if filepaths:
            self.last_explicit_selection_type = 'files'
            # Clear other selections in UI and notify controller
            if hasattr(self, 'text_input'): self.text_input.delete('1.0', tk.END)
            self.controller.handle_folder_selection(None)
            # Update display and notify controller about new file selection
            self.update_selection_display(f"{len(filepaths)} files selected")
            self.controller.handle_files_selection(filepaths)
        # else: User cancelled dialog, do nothing, keep previous selection
        self.reset_progress() # Reset progress bar regardless

    def _select_folder_ui(self):
        """Handles 'Select Folder...' button click."""
        folderpath = filedialog.askdirectory(title="Select Folder to Send")
        if folderpath:
            self.last_explicit_selection_type = 'folder'
            # Clear other selections in UI and notify controller
            if hasattr(self, 'text_input'): self.text_input.delete('1.0', tk.END)
            self.controller.handle_files_selection(None)
            # Update display and notify controller about new folder selection
            folder_name = os.path.basename(folderpath) if folderpath else "Selected Folder"
            self.update_selection_display(f"Folder: {folder_name}")
            self.controller.handle_folder_selection(folderpath)
        # else: User cancelled dialog, do nothing, keep previous selection
        self.reset_progress() # Reset progress bar regardless

    def _on_text_change(self, event=None):
        """Handles text input changes, potentially clearing other selections."""
        if hasattr(self, 'text_input'):
            text_content = self.text_input.get("1.0", tk.END).strip()
            if text_content:
                # If user actively types, make text the primary selection
                if self.last_explicit_selection_type != 'text':
                    self.last_explicit_selection_type = 'text'
                    # Clear file/folder state in controller and update display
                    self.controller.handle_files_selection(None)
                    self.controller.handle_folder_selection(None)
                    self.update_selection_display("Text snippet entered")
            # Always check button state after text change
            self.controller.check_send_button_state_external()
        else:
            print("Warning: _on_text_change called but text_input widget doesn't exist.")

    def _on_device_select_ui(self, event=None):
        """Handles listbox selection and notifies controller."""
        selected_indices = self.devices_listbox.curselection()
        if selected_indices:
            try:
                # Extract only the name part, ignoring the OS tag
                full_display_name = self.devices_listbox.get(selected_indices[0])
                tag_index = full_display_name.rfind(' [')
                selected_name = full_display_name[:tag_index] if tag_index != -1 else full_display_name
                self.controller.handle_device_selection(selected_name)
            except tk.TclError:
                 # Handle error if list is modified during selection
                 self.controller.handle_device_selection(None)
        else:
            # Notify controller that selection was cleared
            self.controller.handle_device_selection(None)

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
        """Notify controller to cancel the current transfer."""
        self.controller.handle_cancel_request()

    def _handle_close_request(self):
        """Called when user clicks the window close button."""
        print("UI: Close button clicked. Requesting shutdown...")
        self.controller.handle_shutdown()

    # --- Public Methods (called by Controller via root.after) ---
    def update_status(self, message):
        """Updates the text in the status bar."""
        # Ensure this runs in the main thread (controller should use root.after)
        self.status_label.config(text=f"Status: {message}")

    def update_selection_display(self, message):
        """Updates the label showing the current selection."""
        # Ensure this runs in the main thread
        self.selection_label.config(text=message)

    def update_device_list(self, action, display_name, os_info=""):
        """Adds or removes a device display name from the listbox."""
        if not display_name: return # Ignore empty names

        # Add OS tag for display
        os_tag = OS_MAP.get(os_info, f"[{os_info[:3]}]" if os_info else "")
        full_display_name = f"{display_name} {os_tag}".strip()

        try:
            # Check if listbox exists before operating on it
            if not hasattr(self, 'devices_listbox') or not self.devices_listbox.winfo_exists():
                 return # Exit if widget is gone (e.g., during shutdown)

            items = list(self.devices_listbox.get(0, tk.END))
            current_selection_index = self.devices_listbox.curselection()
            current_selection_full_name = self.devices_listbox.get(current_selection_index[0]) if current_selection_index else None

            if action == "add":
                # Only add if the exact full name isn't already present
                if full_display_name not in items:
                    self.devices_listbox.insert(tk.END, full_display_name)
            elif action == "remove":
                # Find index based on display_name to handle tag inconsistencies
                found_idx = -1
                item_to_remove_full_name = None
                for idx, item in enumerate(items):
                    # Check if item starts with the base name + space + bracket or is exact match
                    if item.startswith(display_name + " [") or item == display_name:
                        found_idx = idx
                        item_to_remove_full_name = item # Store the actual item name being removed
                        break

                if found_idx != -1:
                    self.devices_listbox.delete(found_idx)
                    # If the *actual* removed item was the selected one, clear controller state
                    if item_to_remove_full_name == current_selection_full_name:
                        self.controller.handle_device_selection(None)

        except tk.TclError as e:
            # Expected error if window is closing during update
            pass # print(f"TclError updating device list (window closed?): {e}")
        except Exception as e:
            print(f"Unexpected error updating device list: {e}")

    def update_button_states(self, send_enabled, cancel_enabled):
         """Updates Send/Cancel/Select button states based on controller logic."""
         try:
             new_send_state = tk.NORMAL if send_enabled else tk.DISABLED
             new_cancel_state = tk.NORMAL if cancel_enabled else tk.DISABLED

             # Check widget existence before configuring (robustness during shutdown)
             if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                 if self.send_button.cget('state') != new_send_state:
                      self.send_button.config(state=new_send_state)
             if hasattr(self, 'cancel_button') and self.cancel_button.winfo_exists():
                 if self.cancel_button.cget('state') != new_cancel_state:
                      self.cancel_button.config(state=new_cancel_state)

             # Enable/disable selection buttons and text input based on whether a transfer is active
             edit_state = tk.NORMAL if not cancel_enabled else tk.DISABLED
             text_edit_state = tk.NORMAL if not cancel_enabled else tk.DISABLED

             if hasattr(self, 'select_files_button') and self.select_files_button.winfo_exists():
                 if self.select_files_button.cget('state') != edit_state:
                     self.select_files_button.config(state=edit_state)
             if hasattr(self, 'select_folder_button') and self.select_folder_button.winfo_exists():
                 if self.select_folder_button.cget('state') != edit_state:
                     self.select_folder_button.config(state=edit_state)

             if hasattr(self, 'text_input') and self.text_input.winfo_exists():
                 current_text_state = self.text_input.cget('state')
                 # Ensure state is compared as string ('normal' vs tk.NORMAL)
                 if str(current_text_state) != str(text_edit_state):
                     self.text_input.config(state=text_edit_state)

         except tk.TclError: pass # Window might be closing
         except Exception as e: print(f"Unexpected error updating button states: {e}")

    def show_error(self, title, message):
        """Displays an error message box."""
        print(f"UI Error: {title} - {message}")
        try:
            # Ensure messagebox runs in main thread
            self.root.after(0, lambda t=title, m=message: messagebox.showerror(t, m))
        except Exception as e: print(f"Failed to show error messagebox: {e}")
        # Reset progress on error
        self.reset_progress()

    def show_success(self, title, message):
         """Displays a success/info message box (for non-text items)."""
         print(f"UI Success: {title} - {message}")
         try:
             # Ensure messagebox runs in main thread
             self.root.after(0, lambda t=title, m=message: messagebox.showinfo(t, m))
         except Exception as e: print(f"Failed to show info messagebox: {e}")
         # Reset progress on success
         self.reset_progress()

    def ask_confirmation(self, title, message):
         """Shows a yes/no dialog. Must be called from main thread."""
         # AppLogic calls this via root.after, ensuring it's in the main thread
         return messagebox.askyesno(title, message)

    def show_selectable_text_popup(self, title, text_content):
        """Creates a Toplevel window with selectable text and a copy button."""
        print(f"UI Displaying selectable text: {title}")
        try:
            # Create the Toplevel window
            popup = tk.Toplevel(self.root)
            popup.title(title)
            popup.geometry("450x300") # Initial size
            popup.minsize(300, 200)

            # Attempt to make it transient (relative to main window) and modal
            try: popup.transient(self.root)
            except tk.TclError: print("Warning: Could not make text popup transient.")
            popup.grab_set() # Make it modal

            # --- Widgets ---
            main_frame = ttk.Frame(popup, padding=10)
            main_frame.pack(expand=True, fill=tk.BOTH)
            main_frame.rowconfigure(0, weight=1)    # Text area expands
            main_frame.columnconfigure(0, weight=1) # Text area expands

            text_widget = scrolledtext.ScrolledText(
                main_frame, wrap=tk.WORD, height=10, width=50, state=tk.NORMAL
            )
            text_widget.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
            text_widget.insert(tk.END, text_content)
            text_widget.config(state=tk.DISABLED) # Make read-only after inserting

            # Button Frame (for Copy and Close)
            button_frame = ttk.Frame(main_frame)
            # Align the frame itself to the bottom-right using grid's sticky
            button_frame.grid(row=1, column=0, sticky="e") # East alignment

            # Copy Button Command
            def _copy_to_clipboard():
                if pyperclip:
                    try:
                        # Get text directly from the widget
                        text_to_copy = text_widget.get("1.0", tk.END).strip()
                        pyperclip.copy(text_to_copy)
                        # Provide visual feedback
                        copy_button.config(text="Copied!", state=tk.DISABLED)
                        # Reset button after a delay
                        popup.after(1500, lambda: copy_button.config(text="Copy", state=tk.NORMAL if pyperclip else tk.DISABLED))
                    except Exception as e:
                        messagebox.showerror("Clipboard Error", f"Could not copy text:\n{e}", parent=popup)
                else:
                    messagebox.showwarning("Clipboard Unavailable",
                                           "Cannot copy text. 'pyperclip' module not installed.",
                                           parent=popup)

            # Create Buttons (packed inside button_frame)
            copy_button = ttk.Button(
                button_frame,
                text="Copy",
                command=_copy_to_clipboard,
                state=(tk.NORMAL if pyperclip else tk.DISABLED) # Enable only if module loaded
            )
            copy_button.pack(side=tk.LEFT, padx=(0, 5)) # Place left, add space to right

            close_button = ttk.Button(button_frame, text="Close", command=popup.destroy)
            close_button.pack(side=tk.LEFT) # Place next to copy button

            # Center the popup relative to the main window (optional but nice)
            popup.update_idletasks() # Ensure window size is calculated before getting geometry
            root_x, root_y = self.root.winfo_x(), self.root.winfo_y()
            root_w, root_h = self.root.winfo_width(), self.root.winfo_height()
            popup_w, popup_h = popup.winfo_width(), popup.winfo_height()
            x = root_x + (root_w // 2) - (popup_w // 2)
            y = root_y + (root_h // 2) - (popup_h // 2)
            popup.geometry(f'+{x}+{y}') # Set position

            # Focus management
            popup.focus_set() # Focus the popup window itself
            text_widget.focus_set() # Focus the text widget for immediate selection/scrolling

            # Wait for the window to be closed (essential for grab_set/modal behavior)
            self.root.wait_window(popup)

        except tk.TclError as e:
             print(f"Failed to create selectable text popup (window closed?): {e}")
             # Fallback to standard message box if Toplevel fails
             self.show_success(title, "[Error displaying popup]\n\n" + text_content)
        except Exception as e:
            import traceback
            print(f"Unexpected error creating selectable text popup: {e}\n{traceback.format_exc()}")
            # Fallback
            self.show_success(title, "[Error displaying popup]\n\n" + text_content)

    def update_progress(self, current_bytes, total_bytes, speed_bps, eta_sec, context_msg=""):
        """Updates the progress bar and status text, including optional context."""
        # Ensure this runs in the main thread
        try:
            # Check if progress bar exists
            if not hasattr(self, 'progress_bar') or not self.progress_bar.winfo_exists():
                return

            if total_bytes > 0:
                percentage = int((current_bytes / total_bytes) * 100)
                safe_percentage = max(0, min(100, percentage)) # Clamp 0-100
                self.progress_bar['value'] = safe_percentage

                speed_str = self._format_speed(speed_bps)
                eta_str = self._format_eta(eta_sec)
                status_text = f"Progress: {safe_percentage}% ({speed_str}, ETA: {eta_str})"
                if context_msg:
                     status_text += f" - {context_msg}" # Append context (e.g., filename)
                self.update_status(status_text)
            else:
                # Handle zero-byte transfers or initial state
                self.progress_bar['value'] = 0
                status_text = "Progress: Calculating..."
                if context_msg: status_text += f" - {context_msg}"
                # Specifically handle 0-byte files/batches
                if total_bytes == 0 and current_bytes == 0:
                    status_text = "Progress: 0 bytes"
                    if context_msg: status_text += f" - {context_msg}"
                self.update_status(status_text)
        except tk.TclError: pass # Ignore errors if window is closing
        except Exception as e: print(f"Error updating progress: {e}")

    def reset_progress(self):
        """Resets the progress bar to 0."""

        # --- Define helper function for root.after ---
        def _do_reset_progress():
            """Internal function to perform the reset safely."""
            try:
                # Check widget existence before configuring
                if hasattr(self, 'progress_bar') and self.progress_bar.winfo_exists():
                    self.progress_bar.config(value=0)
            except tk.TclError:
                pass # Ignore errors if window is closing
            except Exception as e:
                print(f"Error resetting progress bar: {e}")
        # -------------------------------------------

        # Ensure this runs in the main thread by scheduling the helper function
        self.root.after(0, _do_reset_progress)

        # Optionally reset status bar message here too after a short delay
        # self.root.after(100, lambda: self.update_status("Ready.") if not self.controller.is_transfer_active else None)
        
    def add_history_log(self, log_message):
        """Adds a timestamped message to the history text widget."""
        # Ensure this runs in the main thread
        def _update_history():
            try:
                # Check if widget exists and window is valid
                if hasattr(self, 'history_text') and self.history_text.winfo_exists():
                    self.history_text.config(state=tk.NORMAL) # Enable writing
                    timestamp = time.strftime("%H:%M:%S", time.localtime())
                    self.history_text.insert(tk.END, f"{timestamp} - {log_message}\n")
                    self.history_text.see(tk.END) # Scroll to the bottom
                    self.history_text.config(state=tk.DISABLED) # Disable writing again
            except tk.TclError: pass # Expected if window is closing
            except Exception as e: print(f"Unexpected error updating history log: {e}")
        # Schedule update in main thread
        self.root.after(0, _update_history)

    def destroy_window(self):
        """Safely destroys the Tkinter root window."""
        print("UI: Received request to destroy window.")
        try:
            # Check if root exists and is valid before destroying
            if self.root and self.root.winfo_exists():
                self.root.destroy()
                print("UI: Window destroyed.")
            else:
                print("UI: Window already destroyed or invalid.")
        except tk.TclError as e:
            print(f"Error during window destruction (might be already destroyed): {e}")
        except Exception as e:
            print(f"Unexpected error destroying window: {e}")