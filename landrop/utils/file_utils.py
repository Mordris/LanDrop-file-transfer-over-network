import os
from pathlib import Path

# find_downloads_folder is now handled by ConfigManager

def generate_unique_filepath(directory: str, filename: str) -> str:
    """Generates a unique filepath within the directory, appending (n) if necessary."""
    if not directory or not filename:
         # Handle cases where directory or filename might be invalid early
         print(f"Error generating unique path: Invalid directory ('{directory}') or filename ('{filename}').")
         # Fallback or raise error? Returning original might overwrite, but is simple.
         # Let's return a path based on home dir as a last resort for filename part.
         safe_filename = filename if filename else "unknown_file"
         fallback_dir = Path.home() if not directory else Path(directory)
         return str(fallback_dir / safe_filename)


    base_path = Path(directory)
    # Basic sanitization (replace potentially problematic characters) - adjust as needed
    # This is NOT a full security measure.
    safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '.', '-', '_')).rstrip()
    if not safe_filename: safe_filename = "downloaded_file" # Handle empty after sanitization

    original_path = base_path / safe_filename
    target_path = original_path

    counter = 1
    # Limit loop iterations to prevent freezing on weird edge cases
    max_attempts = 1000
    while target_path.exists() and counter <= max_attempts:
        stem = original_path.stem
        suffix = original_path.suffix
        # Append counter like filename (1).txt, filename (2).txt etc.
        target_path = base_path / f"{stem} ({counter}){suffix}"
        counter += 1

    if counter > max_attempts:
         print(f"Warning: Could not find unique filename for '{safe_filename}' after {max_attempts} attempts in '{directory}'. Overwriting or error possible.")
         # Decide on fallback behavior: overwrite last attempt or maybe add timestamp?
         # Returning last attempted path for now.
         return str(target_path)

    return str(target_path)

# --- TLS Certificate Helper (Basic) ---
# Note: This generates insecure self-signed certs suitable only for basic testing.
# Real applications should use proper certificate validation.
def ensure_certificates(cert_dir: Path, key_file: Path, cert_file: Path):
    """Checks for certs, generates self-signed if missing."""
    if key_file.exists() and cert_file.exists():
        print("TLS certificates found.")
        return True

    print("TLS certificates not found. Generating self-signed certificates...")
    try:
        import ssl
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        cert_dir.mkdir(parents=True, exist_ok=True)

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write private key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Generate self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"), # Dummy values
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"LanDrop Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"landrop.local"), # Dummy CN
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Cert valid for 10 years (adjust as needed)
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension( # Add Subject Alternative Name (important!)
             x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), # Allow localhost
             critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())

        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"Self-signed certificates generated in {cert_dir}")
        return True

    except ImportError:
        print("Error: 'cryptography' library not found. Cannot generate certificates.")
        print("Please install it: pip install cryptography")
        return False
    except Exception as e:
        print(f"Error generating certificates: {e}")
        # Clean up potentially partial files
        if key_file.exists(): key_file.unlink()
        if cert_file.exists(): cert_file.unlink()
        return False