import tkinter as tk
from tkinter import ttk, scrolledtext # Use ttk Treeview
from tkinter import filedialog
from tkinter import messagebox
import time
import sys
from pathlib import Path # For icon paths
import os
import traceback # For detailed error logging

# --- PIL for icons ---
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    # Warning printed in __init__

# Conditional pyperclip
try:
    import pyperclip
except ImportError:
    pyperclip = None

# Use constants
try:
    from ..utils.constants import (TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT,
                            TRANSFER_TYPE_MULTI_START, ASSETS_DIR_NAME, ICONS_SUBDIR_NAME,
                            OS_ICON_MAP, SERVICE_TYPE) # Import icon map and SERVICE_TYPE
except ImportError:
    # Fallbacks if constants import fails
    TRANSFER_TYPE_FILE="FILE"; TRANSFER_TYPE_TEXT="TEXT"; TRANSFER_TYPE_MULTI_START="MULTI_START"
    ASSETS_DIR_NAME="assets"; ICONS_SUBDIR_NAME="icons"; OS_ICON_MAP={}; SERVICE_TYPE="_landrop._tcp.local."
    print("Warning (UI): Failed constants import. Icons/Splitting might fail.")


class MainWindow:
    """Handles the Tkinter GUI elements and forwards actions to the controller."""

    def __init__(self, root, controller):
        self.root = root
        self.controller = controller # Instance of AppLogic
        self.root.title("LanDrop")
        self.root.geometry("550x600") # WxH
        self.root.minsize(450, 500)

        # --- Styling ---
        style = ttk.Style(self.root)
        try: # Apply a preferred theme if available
            themes = style.theme_names()
            if 'clam' in themes:
                style.theme_use('clam')
            elif 'vista' in themes and sys.platform == 'win32':
                 style.theme_use('vista')
            elif 'aqua' in themes and sys.platform == 'darwin':
                 style.theme_use('aqua')
            # Add more theme preferences if desired
        except tk.TclError:
            print("Warning: Could not set a preferred theme, using default.")

        # --- Load OS Icons ---
        self.os_icons = {} # Stores PhotoImage objects {os_key: photo_img}
        if not HAS_PIL:
            print("Warning (UI): Pillow library not found (pip install Pillow). OS icons in device list will be disabled.")
        self._load_os_icons()

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

        # --- Device Discovery List (ttk.Treeview) ---
        devices_label = ttk.Label(self.top_frame, text="Discovered Devices:")
        devices_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 2))

        tree_frame = ttk.Frame(self.top_frame) # Frame to hold treeview + scrollbar
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        self.devices_tree = ttk.Treeview(
            tree_frame,
            columns=('device_name',), # Define data columns (only one needed for name)
            show='tree headings', # Show icon column (#0) + data column headings
            yscrollcommand=scrollbar.set,
            selectmode='browse' # Allow only single selection
        )
        scrollbar.config(command=self.devices_tree.yview)

        # Define column headings and appearance
        self.devices_tree.heading('#0', text='OS', anchor=tk.W) # Tree column for icon
        self.devices_tree.heading('device_name', text='Device Name', anchor=tk.W)

        self.devices_tree.column('#0', width=35, minwidth=30, stretch=tk.NO, anchor=tk.CENTER) # Icon column fixed width
        self.devices_tree.column('device_name', anchor=tk.W, stretch=tk.YES) # Name column expands

        # Place Treeview and Scrollbar in grid
        self.devices_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Event binding for selection changes
        self.devices_tree.bind('<<TreeviewSelect>>', self._on_device_select_ui)
        # Dictionary to map Treeview item IDs to full Zeroconf service names
        self.tree_item_to_service_name = {}

        # --- Text Input Area ---
        text_input_frame = ttk.LabelFrame(self.top_frame, text="Text Snippet", padding=5)
        text_input_frame.grid(row=1, column=1, sticky="nsew") # Expand vertically and horizontally if needed
        text_input_frame.rowconfigure(0, weight=1)
        text_input_frame.columnconfigure(0, weight=1)
        self.text_input = scrolledtext.ScrolledText(text_input_frame, height=5, width=25, wrap=tk.WORD)
        self.text_input.grid(row=0, column=0, sticky="nsew")
        self.text_input.bind("<KeyRelease>", self._on_text_change)

        # --- Selection Status Label ---
        self.selection_label = ttk.Label(self.top_frame, text="Nothing selected", wraplength=300) # Wraps if text too long
        self.selection_label.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 2))

        # --- Action Buttons Frame ---
        action_frame = ttk.Frame(self.top_frame)
        action_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        # Selection Buttons
        self.select_files_button = ttk.Button(action_frame, text="Select Files...", command=self._select_files_ui)
        self.select_files_button.pack(side=tk.LEFT, padx=(0, 5))
        self.select_folder_button = ttk.Button(action_frame, text="Select Folder...", command=self._select_folder_ui)
        self.select_folder_button.pack(side=tk.LEFT, padx=(0, 5))
        # Send/Cancel Buttons
        self.send_button = ttk.Button(action_frame, text="Send ->", command=self._send_data_ui, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=(0, 5))
        self.cancel_button = ttk.Button(action_frame, text="Cancel", command=self._cancel_transfer_ui, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 5))

        # --- Progress Bar ---
        self.progress_bar = ttk.Progressbar(self.top_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress_bar.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(5, 5))
        self.progress_bar['value'] = 0

        # --- Bottom Frame (History) ---
        self.bottom_frame = ttk.LabelFrame(self.paned_window, text="History", padding=5)
        self.paned_window.add(self.bottom_frame, weight=1) # Give less initial height
        self.bottom_frame.rowconfigure(0, weight=1); self.bottom_frame.columnconfigure(0, weight=1)
        self.history_text = scrolledtext.ScrolledText(self.bottom_frame, height=6, width=60, wrap=tk.WORD, state=tk.DISABLED)
        self.history_text.grid(row=0, column=0, sticky="nsew")

        # --- Status Bar ---
        self.status_label = ttk.Label(self.root, text="Status: Initializing...", relief=tk.SUNKEN, anchor=tk.W, padding="2 5")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Internal state tracking for UI logic
        self.last_explicit_selection_type = None # 'files', 'folder', or 'text'

        # Window close handling
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close_request)

    def _load_os_icons(self):
        """Loads OS icons using Pillow if available."""
        if not HAS_PIL:
            return # Skip if Pillow not installed

        try:
            # Determine path relative to this ui module file
            script_dir = Path(__file__).parent.resolve()
            # Assumes structure: landrop/ui/main_window.py -> landrop/assets/icons/
            assets_path = script_dir.parent / ASSETS_DIR_NAME / ICONS_SUBDIR_NAME
            print(f"UI: Loading OS icons from: {assets_path}")

            if not assets_path.is_dir():
                 print(f"Warning: Assets/Icons directory not found at {assets_path}")
                 return

            for os_key, filename in OS_ICON_MAP.items():
                icon_path = assets_path / filename
                if icon_path.is_file():
                    try:
                        # Open with Pillow, resize (e.g., 16x16), create PhotoImage
                        # Use LANCZOS for high-quality downscaling
                        img = Image.open(icon_path).resize((16, 16), Image.Resampling.LANCZOS)
                        # Store the PhotoImage object, keyed by the OS identifier
                        self.os_icons[os_key] = ImageTk.PhotoImage(img)
                        # print(f"  Loaded icon: {os_key}")
                    except Exception as e:
                        print(f"  Error loading/processing icon '{filename}': {e}")
                elif os_key != 'unknown': # Don't warn if the fallback is missing (but check later)
                     print(f"  Warning: Icon file not found: {icon_path}")

            # Ensure the essential fallback 'unknown' icon loaded
            if 'unknown' not in self.os_icons:
                print("ERROR: Fallback 'unknown.png' icon is missing or failed to load from assets.")
                # Consider creating a dummy placeholder image here if needed

        except Exception as e:
            print(f"Error finding/loading OS icons folder: {e}")
            traceback.print_exc()
            self.os_icons = {} # Clear icons dictionary on major error

    # --- Helper Formatting Methods ---
    def _format_speed(self, bytes_per_second):
        """Formats speed in B/s, KB/s, MB/s, or GB/s."""
        if bytes_per_second < 1024:
            return f"{bytes_per_second:.1f} B/s"
        elif bytes_per_second < 1024**2:
            return f"{bytes_per_second/1024:.1f} KB/s"
        elif bytes_per_second < 1024**3:
            return f"{bytes_per_second/1024**2:.1f} MB/s"
        else:
            return f"{bytes_per_second/1024**3:.1f} GB/s"

    def _format_eta(self, seconds):
        """Formats ETA in H:MM:SS or MM:SS."""
        if not isinstance(seconds, (int, float)) or seconds < 0 or seconds > 3600 * 24 * 7: # Limit to 1 week
            return "--:--"
        try:
            seconds_int = int(seconds)
            mins, secs = divmod(seconds_int, 60)
            hours, mins = divmod(mins, 60)
            if hours > 0:
                return f"{hours:d}:{mins:02d}:{secs:02d}"
            else:
                return f"{mins:02d}:{secs:02d}"
        except Exception:
            return "--:--" # Fallback on calculation error

    def _format_size(self, size_bytes):
        """Formats size in B, KB, MB, or GB."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/1024**2:.2f} MB"
        else:
            return f"{size_bytes/1024**3:.2f} GB"

    # --- Private UI Event Handlers ---
    def _select_files_ui(self):
        """Handles 'Select Files...' button click."""
        filepaths = filedialog.askopenfilenames(title="Select Files to Send")
        if filepaths: # User selected one or more files
            self.last_explicit_selection_type = 'files'
            if hasattr(self, 'text_input'):
                self.text_input.delete('1.0', tk.END) # Clear text input
            self.controller.handle_folder_selection(None) # Clear folder selection state
            self.update_selection_display(f"{len(filepaths)} files selected") # Update UI label
            self.controller.handle_files_selection(filepaths) # Notify controller
        # else: User cancelled the dialog
        self.reset_progress() # Reset progress bar regardless

    def _select_folder_ui(self):
        """Handles 'Select Folder...' button click."""
        folderpath = filedialog.askdirectory(title="Select Folder to Send", mustexist=True)
        if folderpath: # User selected a folder
            self.last_explicit_selection_type = 'folder'
            if hasattr(self, 'text_input'):
                self.text_input.delete('1.0', tk.END) # Clear text input
            self.controller.handle_files_selection(None) # Clear files selection state
            folder_name = os.path.basename(folderpath) or folderpath # Get folder name
            self.update_selection_display(f"Folder: {folder_name}") # Update UI label
            self.controller.handle_folder_selection(folderpath) # Notify controller
        # else: User cancelled the dialog
        self.reset_progress() # Reset progress bar regardless

    def _on_text_change(self, event=None):
        """Handles text input changes, potentially clearing other selections."""
        if hasattr(self, 'text_input'):
            try:
                text_content = self.text_input.get("1.0", tk.END).strip()
                if text_content:
                    # If user actively types, assume text is the intended selection
                    if self.last_explicit_selection_type != 'text':
                        self.last_explicit_selection_type = 'text'
                        # Clear other selections in the controller
                        self.controller.handle_files_selection(None)
                        self.controller.handle_folder_selection(None)
                        self.update_selection_display("Text snippet entered") # Update UI label
                # Always update button states after text changes
                self.controller.check_send_button_state_external()
            except tk.TclError: pass # Ignore if widget is being destroyed

    def _on_device_select_ui(self, event=None):
        """Handles Treeview selection change."""
        selected_items = self.devices_tree.selection() # Returns tuple of selected item IDs
        if selected_items:
            item_id = selected_items[0] # Get the first (should only be one)
            # Retrieve the full service name associated with this item ID
            full_service_name = self.tree_item_to_service_name.get(item_id)
            if full_service_name:
                # Extract the display name part before the service type suffix
                try:
                    display_name = full_service_name.split(f'.{SERVICE_TYPE}')[0]
                    self.controller.handle_device_selection(display_name) # Notify controller
                except IndexError: # If split fails unexpectedly
                     print(f"Warning: Could not parse display name from '{full_service_name}'")
                     self.controller.handle_device_selection(None)
            else:
                 print(f"Warning: No service name found mapping for Treeview item '{item_id}'")
                 self.controller.handle_device_selection(None)
        else:
            # No item selected
            self.controller.handle_device_selection(None)

    def _send_data_ui(self):
        """Initiates send request after disabling Send button."""
        can_proceed = True
        try: # Immediately disable button
            if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                if str(self.send_button.cget('state')) != str(tk.DISABLED):
                    self.send_button.config(state=tk.DISABLED)
            else: can_proceed = False
        except tk.TclError: can_proceed = False # Window closing

        if not can_proceed: return

        # Determine what to send based on controller state
        stype, item = None, None
        sf=self.controller.selected_filepaths; sd=self.controller.selected_folderpath; st=self.controller.selected_text
        if sf: stype = TRANSFER_TYPE_FILE if len(sf)==1 else TRANSFER_TYPE_MULTI_START; item = sf[0] if stype==TRANSFER_TYPE_FILE else sf; print(f"DBG UI: Send {stype}")
        elif sd: stype = TRANSFER_TYPE_MULTI_START; item = sd; print("DBG UI: Send FOLDER")
        elif st: stype = TRANSFER_TYPE_TEXT; item = st; print("DBG UI: Send TEXT")

        # Proceed if valid, else show error and re-enable button
        if stype and item:
             self.reset_progress()
             self.controller.handle_send_request(item, stype)
        else:
             self.show_error("Send Error","Select files, folder, or enter text to send.")
             try: # Re-enable button
                 if hasattr(self, 'send_button') and self.send_button.winfo_exists(): self.send_button.config(state=tk.NORMAL)
             except Exception as e: print(f"Err re-enable send button: {e}")

    def _cancel_transfer_ui(self):
        """Handles 'Cancel' button click."""
        self.controller.handle_cancel_request()

    def _handle_close_request(self):
        """Handles window close ('X') button click."""
        print("UI: Close button clicked. Requesting shutdown...")
        self.controller.handle_shutdown()

    # --- Public Methods (called by Controller via root.after) ---
    def update_status(self, message):
        """Updates the text in the status bar."""
        try:
            if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                self.status_label.config(text=f"Status: {message}")
        except tk.TclError: pass # Ignore if UI is closing

    def update_selection_display(self, message):
        """Updates the label showing the current selection."""
        try:
            if hasattr(self, 'selection_label') and self.selection_label.winfo_exists():
                self.selection_label.config(text=message)
        except tk.TclError: pass

    def update_device_list(self, action, display_name, os_info="unknown"):
        """Adds or removes a device from the Treeview list with OS icon."""
        if not display_name: return

        # Determine appropriate icon based on os_info string
        os_key_mapped = 'unknown' # Default to unknown icon key
        for key_pattern in OS_ICON_MAP.keys():
             if os_info.lower().startswith(key_pattern):
                  os_key_mapped = key_pattern
                  break # Use first match
        # Get the PhotoImage object, fallback to 'unknown' if specific or fallback missing
        icon_image = self.os_icons.get(os_key_mapped, self.os_icons.get('unknown')) if HAS_PIL else None

        # Construct full service name for internal mapping
        full_service_name = f"{display_name}.{SERVICE_TYPE}"

        try:
            # Ensure treeview exists
            if not hasattr(self, 'devices_tree') or not self.devices_tree.winfo_exists(): return

            # Find if item already exists using the service name mapping
            existing_item_id = None
            for item_id, service_name in self.tree_item_to_service_name.items():
                 if service_name == full_service_name:
                      existing_item_id = item_id
                      break

            if action == "add":
                # Values tuple must match the `columns` definition of Treeview
                item_values = (display_name,)
                if existing_item_id is None:
                    # Insert new item at the end of the root level ('')
                    item_id = self.devices_tree.insert(
                        parent='', index=tk.END,
                        text='', # Text in tree column (#0) is unused here
                        image=icon_image, # OS icon in tree column
                        values=item_values, # Device name in 'device_name' column
                        tags=('device_row',) # Optional tag for styling
                    )
                    # Store the mapping from the new item ID to the full service name
                    self.tree_item_to_service_name[item_id] = full_service_name
                else:
                     # Item already exists, update its display (icon/name if needed)
                     self.devices_tree.item(existing_item_id, image=icon_image, values=item_values)

            elif action == "remove":
                if existing_item_id is not None:
                    # Check if the item to be removed is currently selected
                    is_selected = existing_item_id in self.devices_tree.selection()
                    # Delete from Treeview
                    self.devices_tree.delete(existing_item_id)
                    # Delete from internal mapping
                    del self.tree_item_to_service_name[existing_item_id]
                    # If removed item was selected, clear controller's selection state
                    if is_selected:
                        self.controller.handle_device_selection(None)

        except tk.TclError: pass # Ignore errors during shutdown
        except Exception as e: print(f"Err update device tree: {e}\n{traceback.format_exc()}")

    def update_button_states(self, send_enabled, cancel_enabled):
         """Updates state of Send/Cancel/Select buttons based on controller logic."""
         try:
             # Determine desired states
             send_state = tk.NORMAL if send_enabled else tk.DISABLED
             cancel_state = tk.NORMAL if cancel_enabled else tk.DISABLED
             edit_state = tk.NORMAL if not cancel_enabled else tk.DISABLED # Can edit/select only if not transferring
             text_state = tk.NORMAL if not cancel_enabled else tk.DISABLED

             # --- CORRECTED WIDGET CHECKS ---
             # Update widgets only if their state needs to change and they exist
             # Check each widget explicitly using its known attribute name

             if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                 if str(self.send_button.cget('state')) != str(send_state):
                     self.send_button.config(state=send_state)

             if hasattr(self, 'cancel_button') and self.cancel_button.winfo_exists():
                 if str(self.cancel_button.cget('state')) != str(cancel_state):
                      self.cancel_button.config(state=cancel_state)

             if hasattr(self, 'select_files_button') and self.select_files_button.winfo_exists():
                  if str(self.select_files_button.cget('state')) != str(edit_state):
                     self.select_files_button.config(state=edit_state)

             if hasattr(self, 'select_folder_button') and self.select_folder_button.winfo_exists():
                  if str(self.select_folder_button.cget('state')) != str(edit_state):
                     self.select_folder_button.config(state=edit_state)

             if hasattr(self, 'text_input') and self.text_input.winfo_exists():
                  # Ensure we compare strings for state ('normal' vs tk.NORMAL)
                  if str(self.text_input.cget('state')) != str(text_state):
                     self.text_input.config(state=text_state)
             # --- END CORRECTION ---

         except tk.TclError:
             pass # Ignore errors during window destruction
         except Exception as e:
             print(f"Unexpected error updating button states: {e}")
             traceback.print_exc() # Print traceback for unexpected errors
             
    def show_error(self, title, message):
        """Displays an error message box via main thread."""
        print(f"UI Error: {title} - {message}")
        try:
            # Ensure runs in main thread, modal to root
            self.root.after(0, lambda t=title, m=message: messagebox.showerror(t, m, parent=self.root))
        except Exception as e:
            print(f"Failed to show error messagebox: {e}")
        self.reset_progress() # Always reset progress on error

    def show_success(self, title, message):
         """Displays a success/info message box via main thread."""
         print(f"UI Success: {title} - {message}")
         try:
             # Ensure runs in main thread, modal to root
             self.root.after(0, lambda t=title, m=message: messagebox.showinfo(t, m, parent=self.root))
         except Exception as e:
             print(f"Failed to show success messagebox: {e}")
         self.reset_progress() # Always reset progress on success

    def ask_confirmation(self, title, message):
         """Shows a yes/no dialog. Called from main thread by AppLogic."""
         # Ensure modal to root window
         return messagebox.askyesno(title, message, parent=self.root)

    def show_selectable_text_popup(self, title, text_content):
        """Creates a Toplevel window with selectable text and copy button."""
        print(f"UI Displaying selectable text popup: {title}")
        try:
            popup = tk.Toplevel(self.root)
            popup.title(title)
            popup.geometry("450x300"); popup.minsize(300, 200)
            try: popup.transient(self.root) # Associate with main window
            except tk.TclError: pass
            popup.grab_set() # Make modal

            main_frame = ttk.Frame(popup, padding=10); main_frame.pack(expand=True, fill=tk.BOTH)
            main_frame.rowconfigure(0, weight=1); main_frame.columnconfigure(0, weight=1)

            text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=10, width=50)
            text_widget.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
            text_widget.insert(tk.END, text_content); text_widget.config(state=tk.DISABLED) # Read-only

            button_frame = ttk.Frame(main_frame); button_frame.grid(row=1, column=0, sticky="e") # Align buttons right

            # Inner function for copy command
            def _copy_to_clipboard():
                if pyperclip:
                    try:
                        pyperclip.copy(text_widget.get("1.0", tk.END).strip())
                        copy_button.config(text="Copied!", state=tk.DISABLED) # Feedback
                        popup.after(1500, lambda: copy_button.config(text="Copy", state=tk.NORMAL if pyperclip else tk.DISABLED)) # Reset
                    except Exception as e: messagebox.showerror("Clipboard Error", f"Could not copy:\n{e}", parent=popup)
                else: messagebox.showwarning("Clipboard Unavailable", "'pyperclip' not installed.", parent=popup)

            copy_button = ttk.Button(button_frame, text="Copy", command=_copy_to_clipboard, state=(tk.NORMAL if pyperclip else tk.DISABLED))
            copy_button.pack(side=tk.LEFT, padx=(0, 5))
            close_button = ttk.Button(button_frame, text="Close", command=popup.destroy)
            close_button.pack(side=tk.LEFT)

            # Center popup
            popup.update_idletasks()
            root_x, root_y = self.root.winfo_x(), self.root.winfo_y(); root_w, root_h = self.root.winfo_width(), self.root.winfo_height()
            popup_w, popup_h = popup.winfo_width(), popup.winfo_height()
            x = root_x + (root_w // 2) - (popup_w // 2); y = root_y + (root_h // 2) - (popup_h // 2)
            popup.geometry(f'+{x}+{y}')

            popup.focus_set(); text_widget.focus_set() # Focus text
            self.root.wait_window(popup) # Wait until closed

        except tk.TclError as e: print(f"Failed text popup: {e}") # Window likely closed
        except Exception as e: print(f"Unexpected popup err: {e}\n{traceback.format_exc()}")

    def update_progress(self, current, total, speed, eta, context=""):
        """Updates the progress bar and status text."""
        try:
            if not hasattr(self, 'progress_bar') or not self.progress_bar.winfo_exists(): return
            if total > 0:
                p = int((current / total) * 100); sp = max(0, min(100, p))
                self.progress_bar['value'] = sp
                ss = self._format_speed(speed); es = self._format_eta(eta)
                status = f"Progress: {sp}% ({ss}, ETA: {es})"
                if context: status += f" - {context}"
                self.update_status(status)
            else: # Handle 0-byte or initial state
                self.progress_bar['value'] = 0
                status = "Progress: 0 bytes" if (total == 0 and current == 0) else "Progress: Calculating..."
                if context: status += f" - {context}"
                self.update_status(status)
        except tk.TclError: pass
        except Exception as e: print(f"Err update progress: {e}")

    def reset_progress(self):
        """Resets the progress bar to 0 via main thread using helper function."""
        def _do_reset():
            try:
                if hasattr(self, 'progress_bar') and self.progress_bar.winfo_exists():
                    self.progress_bar.config(value=0)
            except tk.TclError: pass # Ignore if UI closing
            except Exception as e: print(f"Error resetting progress bar: {e}")
        self.root.after(0, _do_reset) # Schedule helper in main loop

    def add_history_log(self, log_message):
        """Adds a timestamped message to the history text widget via main thread."""
        def _update_history():
            try:
                if hasattr(self, 'history_text') and self.history_text.winfo_exists():
                    self.history_text.config(state=tk.NORMAL) # Enable
                    timestamp = time.strftime("%H:%M:%S")
                    self.history_text.insert(tk.END, f"{timestamp} - {log_message}\n")
                    self.history_text.see(tk.END) # Scroll down
                    self.history_text.config(state=tk.DISABLED) # Disable again
            except tk.TclError: pass # Ignore if UI closing
            except Exception as e: print(f"Unexpected error updating history log: {e}")
        # Schedule the update in the main Tkinter thread
        self.root.after(0, _update_history)

    def destroy_window(self):
        """Safely destroys the Tkinter root window."""
        print("UI: Received request to destroy window.")
        try:
            if self.root and self.root.winfo_exists():
                self.root.destroy()
                print("UI: Window destroyed.")
            else:
                print("UI: Window already destroyed or invalid.")
        except tk.TclError as e: print(f"Error during window destruction: {e}")
        except Exception as e: print(f"Unexpected error destroying window: {e}")