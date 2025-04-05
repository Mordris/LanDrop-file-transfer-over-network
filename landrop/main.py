import tkinter as tk
import sys
import os

# If running 'python main.py' from the project root, Python adds the root
# to sys.path, so 'from landrop. ...' should work.
# If running as a module 'python -m landrop ...' (requires __main__.py),
# relative imports '.ui' are preferred within the package.
# Let's assume running 'python main.py' for now.
try:
    from landrop.ui.main_window import MainWindow
    from landrop.core.app_logic import AppLogic
except ImportError as e:
     # If the above fails, maybe the script isn't being run from the project root?
     # Try adding the parent directory to sys.path temporarily.
     print(f"Initial import failed ({e}), attempting path adjustment...")
     script_dir = os.path.dirname(os.path.abspath(__file__))
     parent_dir = os.path.dirname(script_dir)
     if parent_dir not in sys.path:
          sys.path.insert(0, parent_dir)
     print(f"Adjusted sys.path: {sys.path}")
     # Retry imports
     from landrop.ui.main_window import MainWindow
     from landrop.core.app_logic import AppLogic



def main():
    """Sets up and runs the LanDrop application."""
    print("Starting LanDrop Application...")
    # Basic check for Tkinter availability early on
    try:
        tk.Tk().withdraw() # Try creating and hiding a root window
    except tk.TclError as e:
        print("\nError: Tkinter is not available or configured correctly!")
        print(f"({e})")
        print("On Debian/Ubuntu, try: sudo apt update && sudo apt install python3-tk")
        print("On Fedora, try: sudo dnf install python3-tkinter")
        print("On Windows/macOS, Tkinter should be included with Python standard installs.")
        sys.exit(1)
    except Exception as e:
         print(f"\nAn unexpected error occurred checking Tkinter: {e}")
         sys.exit(1)


    try:
        root = tk.Tk()

        # Create the core logic controller, passing the Tk root
        app_logic = AppLogic(root)

        # Create the main UI window, passing the controller
        main_window = MainWindow(root, app_logic)

        # Give the controller a reference back to the window
        # This is crucial for AppLogic to update the UI
        app_logic.set_main_window(main_window)

        # Start the application's background processes (discovery, receiver)
        app_logic.start()

        # Start the Tkinter event loop (blocks until window is closed)
        print("Starting Tkinter main event loop...")
        root.mainloop()

        # mainloop() has returned, meaning the window was closed and
        # the shutdown sequence in AppLogic should have run.
        print("Tkinter main loop finished.")

    # Catch ImportErrors that might occur if dependencies are missing
    # even if Tkinter itself works (e.g., zeroconf)
    except ImportError as e:
         print(f"\nError: Missing required module - {e}")
         print("Please ensure all dependencies are installed:")
         print("1. Activate your virtual environment (if using one).")
         print(f"2. Run: pip install -r {os.path.join(os.path.dirname(__file__), 'requirements.txt')}")
         sys.exit(1)
    except Exception as e:
         print(f"\nAn unexpected error occurred during application setup or runtime: {e}")
         import traceback
         traceback.print_exc() # Print detailed traceback for debugging
         sys.exit(1)

    print("LanDrop Application finished.")


if __name__ == "__main__":
    # Ensure this runs only when the script is executed directly
    main()