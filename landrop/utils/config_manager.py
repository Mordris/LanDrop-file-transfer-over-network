import configparser
import os
from pathlib import Path
import socket
import sys

# Use constants for consistency
from .constants import APP_NAME, DEFAULT_DOWNLOADS_DIR_NAME, CONFIG_FILE_NAME, CONFIG_DIR_NAME

def get_default_config_dir() -> Path:
    """Gets the platform-specific default config directory."""
    if sys.platform == "win32":
        # Use %APPDATA% on Windows
        appdata = os.getenv('APPDATA')
        if appdata:
            return Path(appdata) / APP_NAME
    elif sys.platform == "darwin":
        # Use ~/Library/Application Support on macOS
        return Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        # Use ~/.config on Linux/other Unix-like
        xdg_config_home = os.getenv('XDG_CONFIG_HOME')
        if xdg_config_home:
            return Path(xdg_config_home) / APP_NAME
        else:
            return Path.home() / ".config" / APP_NAME

DEFAULT_CONFIG_PATH = get_default_config_dir() / CONFIG_FILE_NAME

def get_default_device_name():
    """Generates a default device name."""
    try:
        hostname = socket.gethostname()
        return f"{APP_NAME}_{hostname}"
    except Exception:
        return f"{APP_NAME}_UnknownDevice"

def get_default_downloads_path() -> str:
    """Attempts to find the user's Downloads folder."""
    # This reuses the logic previously in file_utils, now centralized
    home = Path.home()
    candidates = [DEFAULT_DOWNLOADS_DIR_NAME, "Download", "download", "downloads"]

    # Basic check for common names first
    for candidate in candidates:
        path = home / candidate
        if path.is_dir():
            return str(path)

    # Platform-specific (Windows Known Folder - less reliable now?)
    if sys.platform == "win32":
        try:
            import ctypes.wintypes
            CSIDL_DOWNLOADS = 37
            SHGFP_TYPE_CURRENT = 0
            buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
            ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DOWNLOADS, None, SHGFP_TYPE_CURRENT, buf)
            win_downloads = Path(buf.value)
            # Check if the path is reasonable (not system32, etc.)
            if win_downloads.is_dir() and "system32" not in str(win_downloads).lower():
                 # print(f"Debug (Config): Found Win Downloads via API: {win_downloads}")
                 return str(win_downloads)
        except Exception:
             # print(f"Debug (Config): Win API failed. Falling back.")
             pass # Fallback handled by common name check above/below

    print(f"Warning (Config): Could not automatically find '{DEFAULT_DOWNLOADS_DIR_NAME}'. Using home directory as fallback.")
    return str(home) # Fallback to home directory if no Downloads found

class ConfigManager:
    """Manages application settings using configparser."""
    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self.config_path = Path(config_path)
        self.config = configparser.ConfigParser()
        self._defaults = {
            'Network': {
                'device_name': get_default_device_name(),
                'enable_tls': 'false' # Default to false for simplicity
            },
            'Preferences': {
                'downloads_directory': get_default_downloads_path(),
                'confirm_receive': 'true',
                'copy_text_to_clipboard': 'true'
            }
        }
        self._ensure_config_exists()
        self.load_settings()

    def _ensure_config_exists(self):
        """Creates the config file and directory with defaults if they don't exist."""
        if not self.config_path.exists():
            print(f"Config file not found at {self.config_path}. Creating with defaults.")
            try:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                # Populate parser with defaults
                for section, options in self._defaults.items():
                    self.config[section] = options
                self.save_settings()
            except OSError as e:
                print(f"Error creating config directory/file: {e}. Using defaults.")
                # Fallback to using defaults in memory if file creation fails
                self.config = configparser.ConfigParser()
                for section, options in self._defaults.items():
                     self.config[section] = options


    def load_settings(self):
        """Loads settings from the config file."""
        if not self.config_path.exists():
             print("Warning: Config file missing on load attempt. Using defaults.")
             self._ensure_config_exists() # Try creating again or load defaults
             return

        try:
             # Read existing file
             self.config.read(self.config_path)

             # Ensure all sections and default keys exist, add if missing
             for section, options in self._defaults.items():
                 if not self.config.has_section(section):
                     self.config[section] = options # Add whole section
                 else:
                     for key, default_value in options.items():
                         if not self.config.has_option(section, key):
                             self.config.set(section, key, default_value) # Add missing key
             # Save back potentially added defaults
             self.save_settings()

        except configparser.Error as e:
            print(f"Error reading config file: {e}. Using defaults.")
            # Reset to defaults in memory on error
            self.config = configparser.ConfigParser()
            for section, options in self._defaults.items():
                 self.config[section] = options


    def save_settings(self):
        """Saves the current settings to the config file."""
        try:
             with open(self.config_path, 'w') as configfile:
                 self.config.write(configfile)
        except OSError as e:
             print(f"Error saving config file to {self.config_path}: {e}")
        except configparser.Error as e:
             print(f"Error writing config data: {e}")


    def get_setting(self, section, key):
        """Gets a setting value, falling back to default if necessary."""
        try:
             # Use fallback mechanism of get() which checks defaults if set
             return self.config.get(section, key, fallback=self._defaults.get(section, {}).get(key))
        except (configparser.NoSectionError, configparser.NoOptionError):
            print(f"Warning: Setting {section}/{key} not found, returning default.")
            return self._defaults.get(section, {}).get(key)

    def get_boolean_setting(self, section, key):
        """Gets a boolean setting value."""
        try:
             return self.config.getboolean(section, key, fallback=self._defaults.get(section, {}).get(key).lower() == 'true')
        except (configparser.NoSectionError, configparser.NoOptionError):
             print(f"Warning: Boolean setting {section}/{key} not found, returning default.")
             return self._defaults.get(section, {}).get(key).lower() == 'true'
        except ValueError: # Handle case where value is not a valid boolean
             print(f"Warning: Invalid boolean value for {section}/{key}. Returning default.")
             return self._defaults.get(section, {}).get(key).lower() == 'true'


    def set_setting(self, section, key, value):
        """Sets a setting value and saves the config."""
        try:
            if not self.config.has_section(section):
                self.config.add_section(section)
            self.config.set(section, key, str(value)) # Ensure value is string
            self.save_settings()
        except configparser.Error as e:
            print(f"Error setting config value {section}/{key}: {e}")