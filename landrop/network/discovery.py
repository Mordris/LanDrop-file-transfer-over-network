import socket
import threading
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, IPVersion
# Use relative imports within the package
from ..constants import SERVICE_TYPE, APP_PORT, APP_NAME
from ..utils.network_utils import get_local_ip_address, get_hostname

class DiscoveryListener(ServiceListener):
    """Handles Zeroconf discovery events and puts updates onto a queue."""
    def __init__(self, update_queue):
        self.update_queue = update_queue

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # print(f"Service {name} updated - Re-adding") # Debug
        # Treat update same as add for simplicity here
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # print(f"Service {name} removed") # Debug
        self.update_queue.put(("remove", name))

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # Request info. Timeout helps prevent blocking the listener thread indefinitely
        # if a device advertises but doesn't respond to info requests quickly.
        info = zc.get_service_info(type_, name, timeout=1000) # 1 second timeout
        if info:
            # print(f"Service {name} added, service info: {info}") # Debug
            # Pass necessary info to the queue
            self.update_queue.put(("add", name, info))
        # else: # Debug
            # This can happen if a device stops responding between announcement and info request
            # print(f"Warning: Could not get info for added service {name} within timeout")


class NetworkDiscovery:
    """Manages Zeroconf service advertising and browsing."""
    def __init__(self, update_queue, stop_event):
        self.update_queue = update_queue
        self.stop_event = stop_event
        self.zeroconf = None
        self.service_info = None
        self.browser = None
        self.listener = DiscoveryListener(self.update_queue)
        self._thread = None
        self.advertised_name = None # Store the name we advertise
        self.device_name = None     # Store the simple device name

    def _run_discovery(self):
        """Internal method to run Zeroconf operations in a thread."""
        try:
            # Force IPv4 for wider compatibility in simple home networks
            # and easier address parsing later.
            self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)

            local_ip = get_local_ip_address()
            hostname = get_hostname()
            # Consistent naming: AppName_Hostname
            self.device_name = f"{APP_NAME}_{hostname}"
            # Unique service instance name for Zeroconf
            service_instance_name = f"{self.device_name}.{SERVICE_TYPE}"
            self.advertised_name = service_instance_name # Store our full advertised name

            self.service_info = ServiceInfo(
                type_=SERVICE_TYPE,
                name=service_instance_name,
                addresses=[socket.inet_aton(local_ip)], # Needs packed bytes
                port=APP_PORT,
                properties={}, # Potential place for OS info {'os': 'linux'} later
                server=f"{hostname}.local.", # Standard Zeroconf server name
            )

            print(f"Registering service: {self.service_info}")
            self.zeroconf.register_service(self.service_info)
            print("Service registered.")
            self.update_queue.put(("status", f"Ready. Advertising as {self.device_name}"))

            print(f"Browsing for other {APP_NAME} services ({SERVICE_TYPE})...")
            self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self.listener)

            # Keep thread alive until stop event is set
            # Check the event periodically instead of blocking indefinitely
            while not self.stop_event.wait(timeout=1.0): # Check every second
                pass # Loop until stop_event is set

            print("Stop event received, shutting down discovery thread.")

        except OSError as e:
             # Handle specific case of network being unreachable during startup
             print(f"Network Error starting Zeroconf: {e}. Check network connection.")
             self.update_queue.put(("status", "Error: Network unavailable?"))
        except Exception as e:
            # Catch other potential errors during Zeroconf operation
            print(f"Error in Zeroconf thread: {e}")
            self.update_queue.put(("status", f"Error: Discovery failed ({e})"))
        finally:
            # --- Cleanup ---
            print("Zeroconf thread cleaning up...")
            if self.zeroconf: # Ensure zeroconf was initialized
                 if self.browser:
                      # print("Closing service browser...") # Browser implicitly closed by zc.close()
                      pass
                 if self.service_info:
                    print("Unregistering service...")
                    try:
                        # Unregistering can also fail if network is down
                        self.zeroconf.unregister_service(self.service_info)
                        print("Service unregistered.")
                    except Exception as e:
                        print(f"Error during service unregistration: {e}")

                 print("Closing Zeroconf instance...")
                 self.zeroconf.close()
                 print("Zeroconf closed.")
            self.zeroconf = None # Clear references
            self.browser = None
            self.service_info = None
            print("Zeroconf thread finished.")


    def start(self):
        """Starts the discovery process in a background thread."""
        if self._thread is None or not self._thread.is_alive():
            print("Starting discovery thread...")
            self.stop_event.clear() # Ensure stop event is clear before starting
            self._thread = threading.Thread(target=self._run_discovery, daemon=True)
            self._thread.start()
        else:
            print("Discovery thread already running.")

    def shutdown(self):
        """Signals the discovery thread to stop and waits for it to join."""
        if self._thread and self._thread.is_alive():
            print("Requesting discovery shutdown...")
            self.stop_event.set()
            # Don't join here immediately, let AppLogic handle overall shutdown timing
            # self._thread.join(timeout=5.0) # Wait briefly for thread to finish
            # if self._thread.is_alive():
            #      print("Warning: Discovery thread did not exit cleanly.")
        else:
             print("Discovery shutdown requested, but thread wasn't running.")


    def get_advertised_name(self):
        """Returns the full service name this instance is advertising as."""
        # Use the stored name because self.service_info might be None during shutdown
        return self.advertised_name