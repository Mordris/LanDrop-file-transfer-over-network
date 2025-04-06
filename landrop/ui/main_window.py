import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import time # Needed for formatting ETA

class MainWindow:
    """Handles the Tkinter GUI elements and forwards actions to the controller."""
    def __init__(self, root, controller):
        self.root = root
        self.controller = controller
        self.root.title("LanDrop")
        self.root.geometry("450x400") # Slightly wider/taller for progress bar
        self.root.minsize(400, 350)

        style = ttk.Style(self.root)
        try:
             themes = style.theme_names()
             if 'clam' in themes: style.theme_use('clam')
             elif 'vista' in themes: style.theme_use('vista')
        except tk.TclError:
             print("Could not set custom theme, using default.")

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        main_frame.rowconfigure(1, weight=1)
        main_frame.columnconfigure(0, weight=1)

        devices_label = ttk.Label(main_frame, text="Discovered Devices:")
        devices_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))

        listbox_frame = ttk.Frame(main_frame)
        listbox_frame.grid(row=1, column=0, sticky="nsew")
        listbox_frame.rowconfigure(0, weight=1)
        listbox_frame.columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.devices_listbox = tk.Listbox(listbox_frame, height=10, yscrollcommand=scrollbar.set, exportselection=False)
        scrollbar.config(command=self.devices_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.devices_listbox.grid(row=0, column=0, sticky="nsew")
        self.devices_listbox.bind('<<ListboxSelect>>', self._on_device_select_ui)

        action_frame = ttk.Frame(main_frame, padding=(0, 10, 0, 0))
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 5)) # Reduced bottom padding
        action_frame.columnconfigure(1, weight=1)

        self.select_file_button = ttk.Button(
            action_frame, text="Select File...", command=self._select_file_ui
        )
        self.select_file_button.grid(row=0, column=0, padx=(0, 5))

        self.send_button = ttk.Button(
            action_frame, text="Send to Selected", command=self._send_data_ui,
            state=tk.DISABLED
        )
        self.send_button.grid(row=0, column=1, sticky=tk.E)

        # --- Progress Bar ---
        self.progress_bar = ttk.Progressbar(
            main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate'
        )
        # Place it below actions, above status bar
        self.progress_bar.grid(row=3, column=0, sticky="ew", pady=(5, 5))
        self.progress_bar['value'] = 0 # Start at 0

        # --- Status Bar ---
        self.status_label = ttk.Label(
            self.root, text="Status: Initializing...",
            relief=tk.SUNKEN, anchor=tk.W, padding="2 5"
        )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

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
        self.controller.handle_file_selection(filepath if filepath else None)
        self.reset_progress() # Reset progress if a new file is selected

    def _on_device_select_ui(self, event=None):
        selected_indices = self.devices_listbox.curselection()
        if selected_indices:
            try:
                selected_name = self.devices_listbox.get(selected_indices[0])
                self.controller.handle_device_selection(selected_name)
            except tk.TclError:
                 self.controller.handle_device_selection(None)
        else:
            self.controller.handle_device_selection(None)

    def _send_data_ui(self):
        self.reset_progress() # Ensure progress starts fresh
        self.controller.handle_send_request()

    def _handle_close_request(self):
        self.controller.handle_shutdown()


    # --- Public Methods (called by Controller via root.after) ---
    def update_status(self, message):
        """Updates the text in the status bar."""
        self.status_label.config(text=f"Status: {message}")

    def update_device_list(self, action, display_name):
        """Adds or removes a device display name."""
        if not display_name: return
        try:
            items = list(self.devices_listbox.get(0, tk.END))
            current_selection_index = self.devices_listbox.curselection()
            current_selection_name = self.devices_listbox.get(current_selection_index[0]) if current_selection_index else None

            if action == "add":
                if display_name not in items:
                    self.devices_listbox.insert(tk.END, display_name)
            elif action == "remove":
                if display_name in items:
                    idx = items.index(display_name)
                    self.devices_listbox.delete(idx)
                    if display_name == current_selection_name:
                        self.controller.handle_device_selection(None)
        except tk.TclError as e:
            print(f"Error updating device list: {e}.")
        except Exception as e:
             print(f"Unexpected error updating device list: {e}")


    def update_send_button_state(self, enabled):
        """Enables or disables the Send button."""
        try:
            # Also disable file selection during transfer? Optional.
            # file_btn_state = tk.NORMAL if enabled else tk.DISABLED
            # self.select_file_button.config(state=file_btn_state)

            new_state = tk.NORMAL if enabled else tk.DISABLED
            if self.send_button.cget('state') != new_state:
                 self.send_button.config(state=new_state)
        except tk.TclError as e:
             print(f"Error updating send button state: {e}.")
        except Exception as e:
            print(f"Unexpected error updating send button state: {e}")


    def show_error(self, title, message):
        """Displays an error message box."""
        print(f"UI Error: {title} - {message}")
        try:
            # Must run in main thread
            self.root.after(0, lambda: messagebox.showerror(title, message))
        except Exception as e:
            print(f"Failed to show error messagebox: {e}")
        # Reset progress on error
        self.reset_progress()


    def show_success(self, title, message):
         """Displays an success/info message box."""
         print(f"UI Success: {title} - {message}")
         try:
             # Must run in main thread
             self.root.after(0, lambda: messagebox.showinfo(title, message))
         except Exception as e:
             print(f"Failed to show info messagebox: {e}")
         # Reset progress on success
         self.reset_progress()


    def update_progress(self, current_bytes, total_bytes, speed_bps, eta_sec):
        """Updates the progress bar and status text."""
        if total_bytes > 0:
            percentage = int((current_bytes / total_bytes) * 100)
            self.progress_bar['value'] = percentage

            speed_str = self._format_speed(speed_bps)
            eta_str = self._format_eta(eta_sec)

            status_text = f"Progress: {percentage}% ({speed_str}, ETA: {eta_str})"
            self.update_status(status_text)
        else:
            # Handle zero-byte files or initial state
             self.progress_bar['value'] = 0
             self.update_status("Progress: Calculating...")


    def reset_progress(self):
        """Resets the progress bar to 0."""
        # Schedule this to run in the main thread
        self.root.after(0, lambda: self.progress_bar.config(value=0))


    def destroy_window(self):
        """Safely destroys the Tkinter root window."""
        print("UI: Received request to destroy window.")
        try:
            self.root.destroy()
            print("UI: Window destroyed.")
        except tk.TclError as e:
            print(f"Error during window destruction: {e}")
        except Exception as e:
            print(f"Unexpected error destroying window: {e}")