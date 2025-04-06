import tkinter as tk
from tkinter import ttk, scrolledtext # Import scrolledtext for history/text input/popup
from tkinter import filedialog
from tkinter import messagebox
import time
import sys # For platform check

# --- NEW: Conditional pyperclip import ---
try:
    import pyperclip
except ImportError:
    pyperclip = None
    # Optional: print a warning here too, though AppLogic already does
    # print("Warning (UI): 'pyperclip' not installed. Copy button in popup will be disabled.")

# Use constants (assuming constants.py is accessible or values hardcoded if needed)
try:
    from ..utils.constants import TRANSFER_TYPE_FILE, TRANSFER_TYPE_TEXT
except ImportError:
    # Fallback values if constants not found (less ideal)
    TRANSFER_TYPE_FILE = "FILE"
    TRANSFER_TYPE_TEXT = "TEXT"


# Map sys.platform to short codes
OS_MAP = {
    'win32': '[Win]',
    'linux': '[Lin]',
    'darwin': '[Mac]', # macOS
}

class MainWindow:
    """Handles the Tkinter GUI elements and forwards actions to the controller."""
    def __init__(self, root, controller):
        self.root = root
        self.controller = controller
        self.root.title("LanDrop")
        # Increased default size
        self.root.geometry("550x550")
        self.root.minsize(450, 450)

        # --- Styling ---
        style = ttk.Style(self.root)
        try:
             themes = style.theme_names()
             # Prefer themes that generally look better cross-platform
             if 'clam' in themes: style.theme_use('clam')
             elif 'vista' in themes: style.theme_use('vista') # Good on Windows if available
             elif 'aqua' in themes: style.theme_use('aqua') # Good on macOS if available
        except tk.TclError:
             print("Could not set a preferred theme, using default.")

        # --- Paned Window for Resizable Sections ---
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned_window.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        # --- Top Frame (Discovery & Actions) ---
        self.top_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(self.top_frame, weight=3) # Give more initial space

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
        self.devices_listbox = tk.Listbox(listbox_frame, height=8, yscrollcommand=scrollbar.set, exportselection=False)
        scrollbar.config(command=self.devices_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.devices_listbox.grid(row=0, column=0, sticky="nsew")
        self.devices_listbox.bind('<<ListboxSelect>>', self._on_device_select_ui)

        # Text Input Area
        text_input_frame = ttk.LabelFrame(self.top_frame, text="Text Snippet", padding=5)
        text_input_frame.grid(row=1, column=1, sticky="nsew", pady=(0,0)) # Expand vertically
        text_input_frame.rowconfigure(0, weight=1)
        text_input_frame.columnconfigure(0, weight=1)

        self.text_input = scrolledtext.ScrolledText(text_input_frame, height=5, width=25, wrap=tk.WORD)
        self.text_input.grid(row=0, column=0, sticky="nsew")
        self.text_input.bind("<KeyRelease>", self._on_text_change) # Check send button state on text change


        # Action Buttons Frame (File/Text Send)
        action_frame = ttk.Frame(self.top_frame)
        action_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))

        self.select_file_button = ttk.Button(
            action_frame, text="Select File...", command=self._select_file_ui
        )
        self.select_file_button.pack(side=tk.LEFT, padx=(0, 5))

        self.send_button = ttk.Button(
            action_frame, text="Send Item ->", command=self._send_data_ui,
            state=tk.DISABLED
        )
        self.send_button.pack(side=tk.LEFT, padx=(0, 5))

        # Cancel Button
        self.cancel_button = ttk.Button(
            action_frame, text="Cancel", command=self._cancel_transfer_ui,
            state=tk.DISABLED # Enabled only during transfer
        )
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 5))

        # Progress Bar
        self.progress_bar = ttk.Progressbar(
            self.top_frame, orient=tk.HORIZONTAL, length=100, mode='determinate'
        )
        self.progress_bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(5, 5))
        self.progress_bar['value'] = 0

        # --- Bottom Frame (History) ---
        self.bottom_frame = ttk.LabelFrame(self.paned_window, text="History", padding=5)
        self.paned_window.add(self.bottom_frame, weight=1) # Less initial space

        self.bottom_frame.rowconfigure(0, weight=1)
        self.bottom_frame.columnconfigure(0, weight=1)

        self.history_text = scrolledtext.ScrolledText(self.bottom_frame, height=6, width=60, wrap=tk.WORD, state=tk.DISABLED)
        self.history_text.grid(row=0, column=0, sticky="nsew")


        # --- Status Bar (outside PanedWindow) ---
        self.status_label = ttk.Label(
            self.root, text="Status: Initializing...",
            relief=tk.SUNKEN, anchor=tk.W, padding="2 5"
        )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Store last selected item type
        self.last_selected_item_type = None # None, 'file', 'text'

        self.root.protocol("WM_DELETE_WINDOW", self._handle_close_request)

    # --- Helper Methods for Formatting ---
    def _format_speed(self, bytes_per_second):
        if bytes_per_second < 1024:
            return f"{bytes_per_second:.1f} B/s"
        elif bytes_per_second < 1024**2:
            return f"{bytes_per_second/1024:.1f} KB/s"
        elif bytes_per_second < 1024**3:
            return f"{bytes_per_second/1024**2:.1f} MB/s"
        else:
            return f"{bytes_per_second/1024**3:.1f} GB/s"

    def _format_eta(self, seconds):
        if seconds < 0 or seconds > 3600 * 24: # Avoid nonsensical values
            return "--:--"
        try:
            (mins, secs) = divmod(int(seconds), 60)
            (hours, mins) = divmod(mins, 60)
            if hours > 0:
                return f"{hours:d}:{mins:02d}:{secs:02d}"
            else:
                return f"{mins:02d}:{secs:02d}"
        except Exception:
             return "--:--" # Catch potential math errors

    # --- Private UI Event Handlers ---
    def _select_file_ui(self):
        filepath = filedialog.askopenfilename()
        if filepath:
             self.last_selected_item_type = 'file'
             # Optional: Clear text input when file selected
             # if hasattr(self, 'text_input'): self.text_input.delete('1.0', tk.END)
        self.controller.handle_file_selection(filepath if filepath else None)
        self.reset_progress()

    def _on_text_change(self, event=None):
        """Handle text input changes."""
        # If user types in the text box, assume they want to send text
        if hasattr(self, 'text_input'): # Check if widget exists
            text_content = self.text_input.get("1.0", tk.END).strip()
            if text_content:
                self.last_selected_item_type = 'text'
                # Optional: Clear file selection if text typed
                # self.controller.handle_file_selection(None) # Might clear status too early
            # Update button state based on whether text exists
            self.controller.check_send_button_state_external()
        else:
             print("Warning: _on_text_change called but text_input widget doesn't exist.")


    def _on_device_select_ui(self, event=None):
        """Handles listbox selection and notifies controller."""
        selected_indices = self.devices_listbox.curselection()
        if selected_indices:
            try:
                # Extract only the name part, ignoring the OS tag for logic
                full_display_name = self.devices_listbox.get(selected_indices[0])
                tag_index = full_display_name.rfind(' [') # Find last bracket for OS tag
                if tag_index != -1:
                     selected_name = full_display_name[:tag_index]
                else:
                     selected_name = full_display_name # No tag found

                self.controller.handle_device_selection(selected_name)
            except tk.TclError:
                 # Handle error if list is modified during selection processing
                 self.controller.handle_device_selection(None)
        else:
            # Notify controller that selection was cleared
            self.controller.handle_device_selection(None)

    def _send_data_ui(self):
        """Determine if sending file or text and notify controller."""
        text_content = ""
        if hasattr(self, 'text_input'): # Check widget exists
            text_content = self.text_input.get("1.0", tk.END).strip()
        file_selected = self.controller.selected_filepath

        send_type = None
        item_to_send = None

        # Prioritize based on last interaction, then check content as fallback
        if self.last_selected_item_type == 'text' and text_content:
            send_type = TRANSFER_TYPE_TEXT
            item_to_send = text_content
        elif self.last_selected_item_type == 'file' and file_selected:
             send_type = TRANSFER_TYPE_FILE
             item_to_send = file_selected
        elif text_content: # Fallback if last type unclear but text exists
            send_type = TRANSFER_TYPE_TEXT
            item_to_send = text_content
        elif file_selected: # Fallback if last type unclear but file exists
             send_type = TRANSFER_TYPE_FILE
             item_to_send = file_selected

        if send_type and item_to_send:
             self.reset_progress()
             self.controller.handle_send_request(item_to_send, send_type)
        else:
             self.show_error("Send Error", "Select a file or enter text to send.")

    def _cancel_transfer_ui(self):
        """Notify controller to cancel the current transfer."""
        self.controller.handle_cancel_request()

    def _handle_close_request(self):
        """Called when user clicks the window close button."""
        self.controller.handle_shutdown()


    # --- Public Methods (called by Controller via root.after) ---
    def update_status(self, message):
        """Updates the text in the status bar. Should be called via root.after."""
        self.status_label.config(text=f"Status: {message}")

    def update_device_list(self, action, display_name, os_info=""):
        """Adds or removes a device display name from the listbox, including OS tag."""
        if not display_name: return # Ignore empty names

        # Add OS tag for display
        os_tag = OS_MAP.get(os_info, f"[{os_info[:3]}]" if os_info else "") # Use first 3 chars if unknown
        full_display_name = f"{display_name} {os_tag}".strip()

        try:
            # Use the full name (with tag) for UI list operations
            items = list(self.devices_listbox.get(0, tk.END))
            current_selection_index = self.devices_listbox.curselection()
            # Get the full name of the currently selected item
            current_selection_full_name = self.devices_listbox.get(current_selection_index[0]) if current_selection_index else None

            if action == "add":
                # Only add if the exact full name isn't already present
                if full_display_name not in items:
                    self.devices_listbox.insert(tk.END, full_display_name)
            elif action == "remove":
                # Find index based on display_name (without tag) to handle potential inconsistencies
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
                    # Check if the *actual* removed item was the selected one
                    if item_to_remove_full_name == current_selection_full_name:
                        self.controller.handle_device_selection(None) # Pass None to clear selection

        except tk.TclError as e:
            print(f"Error updating device list: {e}. Window might be closing.")
        except Exception as e:
             print(f"Unexpected error updating device list: {e}")

    def update_button_states(self, send_enabled, cancel_enabled):
         """Updates Send and Cancel button states. Should be called via root.after."""
         try:
             new_send_state = tk.NORMAL if send_enabled else tk.DISABLED
             new_cancel_state = tk.NORMAL if cancel_enabled else tk.DISABLED

             # Update Send and Cancel buttons
             if self.send_button.cget('state') != new_send_state:
                  self.send_button.config(state=new_send_state)
             if self.cancel_button.cget('state') != new_cancel_state:
                  self.cancel_button.config(state=new_cancel_state)

             # Enable/disable file selection and text input based on whether a transfer is active (cancel_enabled)
             edit_state = tk.NORMAL if not cancel_enabled else tk.DISABLED
             text_edit_state = tk.NORMAL if not cancel_enabled else tk.DISABLED

             if self.select_file_button.cget('state') != edit_state:
                 self.select_file_button.config(state=edit_state)

             if hasattr(self, 'text_input'): # Check if widget exists
                 current_text_state = self.text_input.cget('state')
                 # Ensure state is a string for comparison
                 if str(current_text_state) != str(text_edit_state):
                     self.text_input.config(state=text_edit_state)

         except tk.TclError as e:
              print(f"Error updating button states: {e}. Window might be closing.")
         except Exception as e:
             print(f"Unexpected error updating button states: {e}")

    def show_error(self, title, message):
        """Displays an error message box. Should be called via root.after."""
        print(f"UI Error: {title} - {message}")
        try:
            self.root.after(0, lambda: messagebox.showerror(title, message))
        except Exception as e:
            print(f"Failed to show error messagebox: {e}")
        # Reset progress on error
        self.reset_progress()

    def show_success(self, title, message):
         """Displays a success/info message box (for non-text items). Should be called via root.after."""
         print(f"UI Success: {title} - {message}")
         try:
             self.root.after(0, lambda: messagebox.showinfo(title, message))
         except Exception as e:
             print(f"Failed to show info messagebox: {e}")
         # Reset progress on success
         self.reset_progress()

    def ask_confirmation(self, title, message):
         """Shows a yes/no dialog. Must be called from main thread."""
         # This is called via root.after by AppLogic, so it runs in the main thread
         return messagebox.askyesno(title, message)

    # --- NEW METHOD for Selectable Text Pop-up ---
    def show_selectable_text_popup(self, title, text_content):
        """Creates a Toplevel window with selectable text and a copy button."""
        print(f"UI Displaying selectable text: {title}")
        try:
            # Create the Toplevel window
            popup = tk.Toplevel(self.root)
            popup.title(title)
            popup.geometry("450x300") # Keep initial size
            popup.minsize(300, 200)

            # Attempt to make it transient and modal
            try:
                popup.transient(self.root)
            except tk.TclError:
                 print("Warning: Could not make text popup transient.") # Might fail if root gone
            popup.grab_set() # Make it modal

            # Add Widgets
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

            # --- Button Frame ---
            button_frame = ttk.Frame(main_frame)
            # Align the frame itself to the bottom-right
            button_frame.grid(row=1, column=0, sticky="e")

            # --- Copy Button Command ---
            def _copy_to_clipboard():
                if pyperclip:
                    try:
                        # Get text directly from the widget
                        text_to_copy = text_widget.get("1.0", tk.END).strip()
                        pyperclip.copy(text_to_copy)
                        # Optional feedback: briefly change button text
                        copy_button.config(text="Copied!", state=tk.DISABLED)
                        popup.after(1500, lambda: copy_button.config(text="Copy", state=tk.NORMAL if pyperclip else tk.DISABLED))
                    except Exception as e:
                        # Show error relative to the popup
                        messagebox.showerror("Clipboard Error", f"Could not copy text:\n{e}", parent=popup)
                else:
                    # Should not happen if button is disabled correctly, but belt-and-suspenders
                    messagebox.showwarning("Clipboard Unavailable",
                                           "Cannot copy text. 'pyperclip' module not installed.",
                                           parent=popup)

            # --- Create Buttons ---
            copy_button = ttk.Button(
                button_frame,
                text="Copy",
                command=_copy_to_clipboard,
                # Disable button if pyperclip wasn't imported
                state=(tk.NORMAL if pyperclip else tk.DISABLED)
            )
            # Pack buttons side-by-side within the button_frame
            copy_button.pack(side=tk.LEFT, padx=(0, 5)) # Add padding between buttons

            close_button = ttk.Button(button_frame, text="Close", command=popup.destroy)
            close_button.pack(side=tk.LEFT)


            # Center the popup relative to the main window (optional)
            # ... (centering code remains the same) ...
            popup.update_idletasks()
            root_x = self.root.winfo_x(); root_y = self.root.winfo_y()
            root_w = self.root.winfo_width(); root_h = self.root.winfo_height()
            popup_w = popup.winfo_width(); popup_h = popup.winfo_height()
            x = root_x + (root_w // 2) - (popup_w // 2)
            y = root_y + (root_h // 2) - (popup_h // 2)
            popup.geometry(f'+{x}+{y}')


            # Focus management
            popup.focus_set() # Focus the popup itself
            # Keep focus on text widget initially for selection/scrolling
            text_widget.focus_set()

            # Wait for the window to be closed (makes grab_set effective)
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

    def update_progress(self, current_bytes, total_bytes, speed_bps, eta_sec):
        """Updates the progress bar and status text. Should be called via root.after."""
        if total_bytes > 0:
            percentage = int((current_bytes / total_bytes) * 100)
            safe_percentage = max(0, min(100, percentage)) # Clamp between 0-100
            self.progress_bar['value'] = safe_percentage

            speed_str = self._format_speed(speed_bps)
            eta_str = self._format_eta(eta_sec)
            status_text = f"Progress: {safe_percentage}% ({speed_str}, ETA: {eta_str})"
            self.update_status(status_text)
        else:
            # Handle zero-byte files or initial state
             self.progress_bar['value'] = 0
             # Don't show calculating if size is truly 0
             if total_bytes == 0 and current_bytes == 0:
                  self.update_status("Progress: 0 bytes")
             else:
                  self.update_status("Progress: Calculating...")

    def reset_progress(self):
        """Resets the progress bar to 0. Should be called via root.after."""
        self.root.after(0, lambda: self.progress_bar.config(value=0))

    def add_history_log(self, log_message):
        """Adds a message to the history text widget. Should be called via root.after."""
        def _update_history():
            try:
                # Check if widget exists and window is valid
                if hasattr(self, 'history_text') and self.history_text.winfo_exists():
                    self.history_text.config(state=tk.NORMAL) # Enable writing
                    timestamp = time.strftime("%H:%M:%S", time.localtime())
                    self.history_text.insert(tk.END, f"{timestamp} - {log_message}\n")
                    self.history_text.see(tk.END) # Scroll to the bottom
                    self.history_text.config(state=tk.DISABLED) # Disable writing
            except tk.TclError as e:
                 # Expected if window is closing during update
                 pass # print(f"TclError updating history log (window closed?): {e}")
            except Exception as e:
                 print(f"Unexpected error updating history log: {e}")
        # Schedule update in main thread
        self.root.after(0, _update_history)

    def destroy_window(self):
        """Safely destroys the Tkinter root window."""
        print("UI: Received request to destroy window.")
        try:
            # Check if root exists before destroying
            if self.root and self.root.winfo_exists():
                self.root.destroy()
                print("UI: Window destroyed.")
        except tk.TclError as e:
            print(f"Error during window destruction (might be already destroyed): {e}")
        except Exception as e:
            print(f"Unexpected error destroying window: {e}")