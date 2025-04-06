import tkinter as tk
import sys
import os
import time
import traceback
from pathlib import Path # For icon path handling

# --- PIL for PNG icons ---
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    # Warning will be printed in set_app_icon if needed

# --- Path Adjustment & Imports ---
try:
    # Import necessary components
    from landrop.ui.main_window import MainWindow
    from landrop.core.app_logic import AppLogic
    from landrop.utils.config_manager import ConfigManager
    # Import constants needed in this file
    from landrop.utils.constants import (APP_NAME, ASSETS_DIR_NAME,
                                      APP_ICON_FILENAME_ICO, APP_ICON_FILENAME_PNG)
except ImportError as e:
     # Fallback path adjustment logic
     print(f"Initial import failed ({e}), attempting path adjustment...")
     script_dir = os.path.dirname(os.path.abspath(__file__))
     # Assumes structure: project_root/landrop/main.py -> project_root is parent
     project_root = Path(script_dir).parent.resolve()
     if str(project_root) not in sys.path:
          sys.path.insert(0, str(project_root))
          print(f"Added project root to sys.path: {project_root}")
          try: # Retry imports
               from landrop.ui.main_window import MainWindow
               from landrop.core.app_logic import AppLogic
               from landrop.utils.config_manager import ConfigManager
               from landrop.utils.constants import (APP_NAME, ASSETS_DIR_NAME,
                                                 APP_ICON_FILENAME_ICO, APP_ICON_FILENAME_PNG)
               print("Imports successful after path adjustment.")
          except ImportError as inner_e:
               print(f"\nFATAL ERROR: Import failed after path adjustment: {inner_e}")
               print("Please ensure the script is run correctly or the 'landrop' package is installed.")
               sys.exit(1)
     else:
          print(f"\nFATAL ERROR: Project root likely already in path, but imports failed: {e}")
          print("Check for circular imports or missing __init__.py files.")
          sys.exit(1)


def set_app_icon(root_window: tk.Tk):
    """Attempts to set the application icon for the main window."""
    try:
        # Determine the base path (directory containing the 'landrop' package)
        # Assumes main.py is directly inside the 'landrop' package directory
        package_dir = Path(__file__).parent.resolve()
        assets_path = package_dir / ASSETS_DIR_NAME # landrop/assets/

        ico_path = assets_path / APP_ICON_FILENAME_ICO # landrop/assets/LanDrop.ico
        png_path = assets_path / APP_ICON_FILENAME_PNG # landrop/assets/LanDrop.png
        print(f"Looking for app icons in: {assets_path}")

        icon_set = False
        # --- Windows: Prefer .ico ---
        if sys.platform == "win32" and ico_path.is_file():
            try:
                print(f"Attempting to set icon (win32 ico): {ico_path}")
                # iconbitmap needs the path string
                root_window.iconbitmap(default=str(ico_path))
                icon_set = True
                print("  Set icon using .ico")
            except Exception as ico_err:
                print(f"  Failed to set .ico: {ico_err}")

        # --- Other OS (or Windows fallback): Try .png ---
        if not icon_set and png_path.is_file():
            print(f"Attempting to set icon (png): {png_path}")
            if HAS_PIL:
                 try:
                      img = Image.open(png_path)
                      # Create PhotoImage using Pillow
                      photo = ImageTk.PhotoImage(img)
                      # Store reference on root window to prevent garbage collection!
                      root_window.app_icon_ref_png = photo
                      # Set icon for this window and potentially future Toplevels
                      root_window.iconphoto(True, photo)
                      icon_set = True
                      print("  Set icon using Pillow PNG.")
                 except Exception as pil_e:
                      print(f"  Error setting icon with Pillow: {pil_e}")
                      traceback.print_exc() # Show details if PIL fails
            else:
                 # Try Tkinter's built-in PhotoImage (less reliable for PNG, needs GIF/PGM)
                 print("  Pillow not found, trying Tkinter's PhotoImage (may fail)...")
                 try:
                      photo = tk.PhotoImage(file=str(png_path))
                      root_window.app_icon_ref_tk = photo # Keep reference
                      root_window.iconphoto(True, photo)
                      icon_set = True
                      print("  Set icon using Tkinter PhotoImage (might not display correctly).")
                 except tk.TclError as tcl_e:
                      print(f"  Tkinter PhotoImage failed for PNG: {tcl_e}")
                      # Final fallback: Try ICO even on non-windows if PNG failed
                      if not icon_set and ico_path.is_file() and sys.platform != "win32":
                           print(f"  Trying ICO fallback on non-Windows: {ico_path}")
                           try:
                                root_window.iconbitmap(default=str(ico_path))
                                icon_set = True
                                print("  Set icon using .ico (might not work on this OS).")
                           except Exception as ico_e:
                                print(f"  ICO fallback also failed: {ico_e}")

        # --- Final Check ---
        if not icon_set:
            print("Warning: Application icon could not be set (icon files not found in assets/, or PIL missing/failed?).")

    except Exception as e:
        print(f"Error in set_app_icon: {e}")
        traceback.print_exc()


def main():
    """Sets up and runs the LanDrop application."""
    print(f"--- Starting {APP_NAME} ---")

    # --- Check Tkinter availability ---
    try:
        temp_root = tk.Tk(); temp_root.withdraw(); temp_root.destroy()
        print("Tkinter check successful.")
    except tk.TclError as e:
        print("\nFATAL ERROR: Tkinter not available/configured!")
        print(f"({e})")
        # Add platform-specific advice if possible
        sys.exit(1)
    except Exception as e:
         print(f"\nFATAL ERROR: Tkinter check failed unexpectedly: {e}")
         traceback.print_exc()
         sys.exit(1)

    # --- Initialize Configuration ---
    print("Loading configuration...")
    config_manager = None
    try:
        config_manager = ConfigManager()
    except Exception as e:
        print(f"FATAL ERROR: Failed to initialize config manager: {e}")
        traceback.print_exc()
        sys.exit(1)

    # --- Main Application Setup ---
    root = None # Define root outside try for finally clause
    app_logic = None
    try:
        print("Initializing Tkinter root window...")
        root = tk.Tk()
        root.withdraw() # Keep root window hidden initially

        # --- Set Application Icon ---
        set_app_icon(root) # Call the function to set the icon

        print("Creating application logic...")
        app_logic = AppLogic(root, config_manager) # Create core controller

        print("Creating main UI window...")
        main_window = MainWindow(root, app_logic) # Create UI

        app_logic.set_main_window(main_window) # Link logic back to UI

        print("Starting AppLogic background services...")
        app_logic.start() # Start discovery, receiver, polling

        print("Making UI visible...")
        root.deiconify() # Show the window
        root.lift() # Try to bring to front
        root.attributes('-topmost', True) # Force topmost initially
        root.after_idle(root.attributes, '-topmost', False) # Release topmost after idle

        # --- Start Tkinter Event Loop ---
        print("--- Entering Tkinter main event loop ---")
        root.mainloop() # Blocks until window is closed
        print("--- Tkinter main event loop finished ---")

    # --- Error Handling during setup/runtime ---
    except Exception as e:
         print(f"\nFATAL RUNTIME ERROR: {e}")
         traceback.print_exc()
         # Attempt graceful shutdown if possible
         if app_logic:
              print("Attempting graceful shutdown after error...")
              app_logic.handle_shutdown()
              time.sleep(1) # Give shutdown a moment
         sys.exit(1)
    finally:
         # --- Cleanup on exit ---
         print("Application shutdown sequence initiated.")
         # Ensure shutdown is called if mainloop exits unexpectedly or normally
         if app_logic and hasattr(app_logic, 'stop_event') and not app_logic.stop_event.is_set():
             print("Main loop exited, ensuring shutdown signal is sent...")
             app_logic.handle_shutdown()
             # Give threads a moment before script fully exits
             time.sleep(1.0)

    print(f"--- {APP_NAME} Application finished ---")


if __name__ == "__main__":
    # Ensure script runs within the main function block
    main()