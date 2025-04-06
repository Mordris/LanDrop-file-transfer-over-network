import tkinter as tk
import sys
import os

# Attempt standard import first
try:
    from landrop.ui.main_window import MainWindow
    from landrop.core.app_logic import AppLogic
    from landrop.utils.config_manager import ConfigManager
    from landrop.utils.constants import APP_NAME
except ImportError as e:
     # Fallback path adjustment if running script directly from unusual location
     print(f"Initial import failed ({e}), attempting path adjustment...")
     script_dir = os.path.dirname(os.path.abspath(__file__))
     parent_dir = os.path.dirname(script_dir) # Assumes main.py is in project root
     if script_dir not in sys.path: sys.path.insert(0, script_dir)
     if parent_dir not in sys.path: sys.path.insert(0, parent_dir)
     print(f"Adjusted sys.path trying to find 'landrop' package: {sys.path}")
     # Retry imports after path adjustment
     from landrop.ui.main_window import MainWindow
     from landrop.core.app_logic import AppLogic
     from landrop.utils.config_manager import ConfigManager
     from landrop.utils.constants import APP_NAME


def main():
    """Sets up and runs the LanDrop application."""
    print(f"Starting {APP_NAME} Application...")

    # --- Check Tkinter availability early ---
    try:
        temp_root = tk.Tk()
        temp_root.withdraw()
        temp_root.destroy()
    except tk.TclError as e:
        print("\nFatal Error: Tkinter is not available or configured correctly!")
        print(f"({e})")
        # ... (platform-specific instructions remain same) ...
        sys.exit(1)
    except Exception as e:
         print(f"\nFatal Error: An unexpected error occurred checking Tkinter: {e}")
         sys.exit(1)

    # --- Initialize Configuration ---
    print("Loading configuration...")
    config_manager = ConfigManager()

    # --- Main Application Setup ---
    root = None # Ensure root is defined for finally block
    app_logic = None
    try:
        root = tk.Tk()
        root.withdraw() # Hide root window initially

        # Create the core logic controller, passing Tk root and config
        app_logic = AppLogic(root, config_manager)

        # Create the main UI window, passing the controller
        main_window = MainWindow(root, app_logic)

        # Give the controller a reference back to the window
        app_logic.set_main_window(main_window)

        # Start the application's background processes
        app_logic.start() # Starts discovery, receiver, polling

        # Make window visible only after setup
        root.deiconify()

        # Start the Tkinter event loop
        print("Starting Tkinter main event loop...")
        root.mainloop() # Blocks until window is closed

        print("Tkinter main loop finished.")

    # --- Error Handling ---
    except ImportError as e:
         print(f"\nFatal Error: Missing required module - {e}")
         print("Please ensure all dependencies are installed:")
         print("1. Activate your virtual environment (if using one).")
         print(f"2. Run: pip install -r requirements.txt")
         sys.exit(1)
    except Exception as e:
         print(f"\nFatal Error: An unexpected error occurred during application setup or runtime.")
         import traceback
         traceback.print_exc()
         sys.exit(1)
    finally:
         # --- Cleanup ---
         print("Application shutdown sequence initiated from main.")
         # AppLogic's handle_shutdown should have been called by window close,
         # but ensure stop event is set if mainloop exits unexpectedly.
         if app_logic and hasattr(app_logic, 'stop_event'):
             app_logic.stop_event.set()
             # Give threads a moment to potentially react before script exits fully
             time.sleep(0.7)

    print(f"{APP_NAME} Application finished.")


if __name__ == "__main__":
    main()