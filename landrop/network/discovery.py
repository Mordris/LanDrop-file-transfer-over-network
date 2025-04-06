import socket
import threading
import sys # Import sys for platform info
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, IPVersion

# Use relative imports within the package
from ..utils.constants import SERVICE_TYPE, APP_PORT
from ..utils.network_utils import get_local_ip_address, get_hostname
# Import config manager to get device name
from ..utils.config_manager import ConfigManager

class DiscoveryListener(ServiceListener):
    """Handles Zeroconf discovery events and puts updates onto a queue."""
    def __init__(self, update_queue):
        self.update_queue = update_queue

    def _parse_properties(self, properties_bytes):
        """Safely parse Zeroconf properties."""
        properties = {}
        if not properties_bytes:
            return properties
        try:
            # Properties are key=value pairs, null-separated? Or just dict? Let's assume dict-like bytes.
            # Zeroconf library often handles this decoding. Let's check info.properties directly.
            # This helper might not be needed if info.properties is already a dict.
            pass # Placeholder if manual parsing needed later
        except Exception as e:
            print(f"Error parsing service properties: {e}")
        return properties

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # Re-query info on update
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.update_queue.put(("remove", name))

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name, timeout=1500) # Slightly longer timeout
        if info:
            # Extract OS from properties if available
            os_info = "Unknown"
            try:
                 # Properties are bytes keys/values, decode them
                 decoded_props = {k.decode('utf-8'): v.decode('utf-8') for k, v in info.properties.items()}
                 os_info = decoded_props.get('os', 'Unknown')
            except Exception:
                 pass # Ignore decoding errors, stick with Unknown

            # Put name, info obj, and extracted os_info onto queue
            self.update_queue.put(("add", name, info, os_info))
        # else:
            # print(f"Warning: Could not get info for added service {name} within timeout")


class NetworkDiscovery:
    """Manages Zeroconf service advertising and browsing."""
    def __init__(self, update_queue, stop_event, config: ConfigManager): # Add config
        self.update_queue = update_queue
        self.stop_event = stop_event
        self.config = config # Store config manager
        self.zeroconf = None
        self.service_info = None
        self.browser = None
        self.listener = DiscoveryListener(self.update_queue)
        self._thread = None
        self.advertised_name = None
        self.device_name = None # Store the user-configured device name

    def _run_discovery(self):
        """Internal method to run Zeroconf operations in a thread."""
        try:
            self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)

            local_ip = get_local_ip_address()
            # --- Use device name from config ---
            self.device_name = self.config.get_setting('Network', 'device_name')
            service_instance_name = f"{self.device_name}.{SERVICE_TYPE}"
            self.advertised_name = service_instance_name

            # --- Add OS property ---
            properties = {'os': sys.platform}
            # Encode properties for ServiceInfo
            encoded_props = {k.encode('utf-8'): v.encode('utf-8') for k, v in properties.items()}

            self.service_info = ServiceInfo(
                type_=SERVICE_TYPE,
                name=service_instance_name,
                addresses=[socket.inet_aton(local_ip)],
                port=APP_PORT,
                properties=encoded_props, # Pass encoded properties
                server=f"{socket.gethostname()}.local.", # Use actual hostname here
            )

            print(f"Registering service: {self.service_info}")
            self.zeroconf.register_service(self.service_info)
            print("Service registered.")
            self.update_queue.put(("status", f"Ready. Advertising as {self.device_name}"))

            print(f"Browsing for other services ({SERVICE_TYPE})...")
            self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self.listener)

            while not self.stop_event.wait(timeout=1.0):
                pass

            print("Stop event received, shutting down discovery thread.")

        except OSError as e:
             print(f"Network Error starting Zeroconf: {e}.")
             self.update_queue.put(("status", "Error: Network unavailable?"))
        except Exception as e:
            print(f"Error in Zeroconf thread: {e}")
            self.update_queue.put(("status", f"Error: Discovery failed ({e})"))
        finally:
            print("Zeroconf thread cleaning up...")
            if self.zeroconf:
                 # ... (unregistering and closing zeroconf remains the same) ...
                 if self.service_info:
                    print("Unregistering service...")
                    try:
                        self.zeroconf.unregister_service(self.service_info)
                        print("Service unregistered.")
                    except Exception as e:
                        print(f"Error during service unregistration: {e}")
                 print("Closing Zeroconf instance...")
                 self.zeroconf.close()
                 print("Zeroconf closed.")
            self.zeroconf = None
            self.browser = None
            self.service_info = None
            print("Zeroconf thread finished.")

    # start() and shutdown() methods remain structurally the same
    def start(self):
        if self._thread is None or not self._thread.is_alive():
            print("Starting discovery thread...")
            self.stop_event.clear()
            self._thread = threading.Thread(target=self._run_discovery, daemon=True)
            self._thread.start()
        else:
            print("Discovery thread already running.")

    def shutdown(self):
        if self._thread and self._thread.is_alive():
            print("Requesting discovery shutdown...")
            self.stop_event.set()
        else:
             print("Discovery shutdown requested, but thread wasn't running.")


    def get_advertised_name(self):
        return self.advertised_name