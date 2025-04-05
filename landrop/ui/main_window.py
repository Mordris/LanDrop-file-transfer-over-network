import tkinter as tk
from tkinter import ttk
from tkinter import filedialog # Needed for file selection
from tkinter import messagebox # Import messagebox for show_error

class MainWindow:
    """Handles the Tkinter GUI elements and forwards actions to the controller."""
    def __init__(self, root, controller):
        self.root = root
        self.controller = controller # Reference to AppLogic
        self.root.title("LanDrop") # Set standard title
        self.root.geometry("400x350") # Adjusted height
        self.root.minsize(350, 300) # Prevent window becoming too small

        # Style configuration
        style = ttk.Style(self.root)
        # You can experiment with themes if available on your system
        # print(style.theme_names()) # See available themes
        try:
             # Try using a theme that might look better across platforms
             # 'clam', 'alt', 'default', 'classic' are common
             # On Windows, 'vista' might be available. On Linux, often 'clam'.
             themes = style.theme_names()
             if 'clam' in themes: style.theme_use('clam')
             elif 'vista' in themes: style.theme_use('vista')
             # else default theme is used
        except tk.TclError:
             print("Could not set custom theme, using default.")


        # --- UI Elements ---
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Configure grid layout for main_frame
        main_frame.rowconfigure(1, weight=1) # Allow listbox to expand vertically
        main_frame.columnconfigure(0, weight=1) # Allow listbox/scrollbar to expand horizontally

        devices_label = ttk.Label(main_frame, text="Discovered Devices:")
        devices_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))

        # Frame to hold listbox and scrollbar together
        listbox_frame = ttk.Frame(main_frame)
        listbox_frame.grid(row=1, column=0, sticky="nsew") # Expand in all directions
        listbox_frame.rowconfigure(0, weight=1)
        listbox_frame.columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.devices_listbox = tk.Listbox(listbox_frame, height=10, yscrollcommand=scrollbar.set, exportselection=False)
        scrollbar.config(command=self.devices_listbox.yview)

        scrollbar.grid(row=0, column=1, sticky="ns") # Place scrollbar to the right
        self.devices_listbox.grid(row=0, column=0, sticky="nsew") # Listbox fills the frame

        # Bind selection changes to the private handler
        self.devices_listbox.bind('<<ListboxSelect>>', self._on_device_select_ui)

        action_frame = ttk.Frame(main_frame, padding=(0, 10, 0, 0)) # Padding top
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0)) # Stick horizontally
        action_frame.columnconfigure(1, weight=1) # Allow spacer/send button push right

        self.select_file_button = ttk.Button(
            action_frame, text="Select File...", command=self._select_file_ui
        )
        self.select_file_button.grid(row=0, column=0, padx=(0, 5))

        self.send_button = ttk.Button(
            action_frame, text="Send to Selected", command=self._send_data_ui,
            state=tk.DISABLED # Start disabled
        )
        self.send_button.grid(row=0, column=1, sticky=tk.E) # Align Send button to the right


        # --- Status Bar ---
        self.status_label = ttk.Label(
            self.root, text="Status: Initializing...",
            relief=tk.SUNKEN, anchor=tk.W, padding="2 5"
        )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X) # Use pack for status bar

        # Handle window closing via the controller
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close_request)

    # --- Private UI Event Handlers ---
    def _select_file_ui(self):
        """Opens file dialog and notifies controller."""
        filepath = filedialog.askopenfilename()
        # Notify controller whether a file was selected or cancelled
        self.controller.handle_file_selection(filepath if filepath else None)

    def _on_device_select_ui(self, event=None):
        """Handles listbox selection and notifies controller."""
        selected_indices = self.devices_listbox.curselection()
        if selected_indices:
            try:
                selected_name = self.devices_listbox.get(selected_indices[0])
                self.controller.handle_device_selection(selected_name)
            except tk.TclError:
                 # Can happen if list is modified while processing selection
                 self.controller.handle_device_selection(None)
        else:
            # Notify controller that selection was cleared
            self.controller.handle_device_selection(None)

    def _send_data_ui(self):
        """Notifies controller to initiate send."""
        # Add confirmation dialog? Optional
        # if messagebox.askyesno("Confirm Send", f"Send selected file to {self.controller.selected_device_display_name}?"):
        #      self.controller.handle_send_request()
        self.controller.handle_send_request()

    def _handle_close_request(self):
        """Called when user clicks the window close button."""
        print("UI: Close button clicked.")
        # Optionally ask for confirmation
        # if messagebox.askokcancel("Quit", "Do you want to quit LanDrop?"):
        #     self.controller.handle_shutdown()
        self.controller.handle_shutdown()


    # --- Public Methods (called by Controller via root.after) ---
    def update_status(self, message):
        """Updates the text in the status bar. Should be called via root.after."""
        self.status_label.config(text=f"Status: {message}")
        # print(f"UI Status: {message}") # Console logging can be excessive here

    def update_device_list(self, action, display_name):
        """Adds or removes a device display name. Should be called via root.after."""
        if not display_name: return # Ignore empty names

        try:
            items = list(self.devices_listbox.get(0, tk.END))
            current_selection_index = self.devices_listbox.curselection()
            current_selection_name = self.devices_listbox.get(current_selection_index[0]) if current_selection_index else None

            if action == "add":
                if display_name not in items:
                    self.devices_listbox.insert(tk.END, display_name)
                    # print(f"UI: Added '{display_name}' to list.") # Debug
            elif action == "remove":
                if display_name in items:
                    idx = items.index(display_name)
                    self.devices_listbox.delete(idx)
                    # print(f"UI: Removed '{display_name}' from list.") # Debug
                    # Check if the removed item was the selected one
                    if display_name == current_selection_name:
                        # If the currently selected item is removed, explicitly clear the controller's state
                        self.controller.handle_device_selection(None)

            # Ensure listbox selection state is consistent after modification
            # This helps if items are removed/added causing indices to change.
            # self._on_device_select_ui() # Calling this directly can cause issues if called from outside main thread
            # It's safer to let the controller manage its state based on the removal notice.

        except tk.TclError as e:
            print(f"Error updating device list: {e}. Window might be closing.")
        except Exception as e:
             print(f"Unexpected error updating device list: {e}")


    def update_send_button_state(self, enabled):
        """Enables or disables the Send button. Should be called via root.after."""
        try:
            new_state = tk.NORMAL if enabled else tk.DISABLED
            # Only update if the state actually changes to avoid unnecessary redraws
            if self.send_button.cget('state') != new_state:
                 self.send_button.config(state=new_state)
                 # print(f"UI: Send button {'enabled' if enabled else 'disabled'}") # Debug
        except tk.TclError as e:
             print(f"Error updating send button state: {e}. Window might be closing.")
        except Exception as e:
            print(f"Unexpected error updating send button state: {e}")

    def show_error(self, title, message):
        """Displays an error message box. Can be called directly if from main thread,
           but safer via root.after if called from controller potentially."""
        print(f"UI Error Display: {title} - {message}") # Log error
        try:
            # Messagebox must run in the main Tk thread
            self.root.after(0, lambda: messagebox.showerror(title, message))
        except Exception as e:
            print(f"Failed to show error messagebox: {e}")

    def destroy_window(self):
        """Safely destroys the Tkinter root window."""
        print("UI: Received request to destroy window.")
        # No need for root.after here, as this is likely called from AppLogic's _destroy_ui
        # which is already scheduled with root.after
        try:
            self.root.destroy()
            print("UI: Window destroyed.")
        except tk.TclError as e:
            print(f"Error during window destruction (might be already destroyed): {e}")
        except Exception as e:
            print(f"Unexpected error destroying window: {e}")