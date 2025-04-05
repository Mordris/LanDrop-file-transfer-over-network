import os
import sys
from pathlib import Path

import os
import sys
from pathlib import Path

def find_downloads_folder() -> str | None:
    """Attempts to find the user's Downloads folder across platforms."""
    home = Path.home()
    # --- BEGIN MODIFICATION ---
    print(f"Debug: Home directory detected as: {home}") # Add this to see what home path is found
    # --- END MODIFICATION ---
    candidates = ["Downloads", "Download", "download", "downloads"] # Common names

    # --- BEGIN MODIFICATION ---
    # Comment out or delete the Windows API block
    # if sys.platform == "win32":
    #     try:
    #         import ctypes.wintypes
    #         CSIDL_DOWNLOADS = 37
    #         SHGFP_TYPE_CURRENT = 0
    #         buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    #         ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DOWNLOADS, None, SHGFP_TYPE_CURRENT, buf)
    #         win_downloads = Path(buf.value)
    #         if win_downloads.is_dir():
    #             print(f"Debug: Found Windows Downloads via known folder: {win_downloads}")
    #             return str(win_downloads)
    #     except (ImportError, AttributeError, OSError) as e:
    #         print(f"Could not use Windows API to find Downloads folder: {e}. Falling back.")
    #         pass
    # --- END MODIFICATION ---


    # General check for common names within the home directory (NOW THE PRIMARY METHOD)
    for candidate in candidates:
        path = home / candidate
        if path.is_dir():
            print(f"Debug: Found Downloads folder by name: {path}") # Keep this debug print
            return str(path)

    # Last resort
    print("Warning: Could not automatically find a 'Downloads' folder in the home directory.")
    return None

def generate_unique_filepath(directory: str, filename: str) -> str:
    # ... (rest of the function remains the same) ...
    base_path = Path(directory)
    original_path = base_path / filename
    target_path = original_path

    counter = 1
    while target_path.exists():
        stem = original_path.stem
        suffix = original_path.suffix
        target_path = base_path / f"{stem} ({counter}){suffix}"
        counter += 1
        if counter > 999:
             print(f"Error: Could not find unique filename for {filename} after 999 attempts.")
             return str(target_path)

    return str(target_path)
