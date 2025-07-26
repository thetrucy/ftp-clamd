import socket, tempfile, os
import pyclamd
import sys # Import sys for sys.exit
import subprocess
# This is the port YOUR CUSTOM SERVER (clam_server.py) will listen on for YOUR FTP CLIENT
HOST = '0.0.0.0' # Listen on all available interfaces
PORT = 12067     # <--- YOUR CUSTOM SERVER'S LISTENING PORT (for ftp_client.py)

# This is where YOUR CUSTOM SERVER (clam_server.py) will connect to the REAL CLAMAV DAEMON
CLAMAV_DAEMON_HOST = '127.0.0.1' # Connect to ClamAV daemon on localhost
CLAMAV_DAEMON_PORT = 3310        # <--- REAL CLAMAV DAEMON'S TCP PORT (from clamd.conf)

BUFFER_SIZE = 4096

# --- Establish connection to the real ClamAV daemon ONCE when the server starts ---

clamd = None
try:
    # Connect to the actual ClamAV daemon via TCP
    clamd = pyclamd.ClamdNetworkSocket(host=CLAMAV_DAEMON_HOST, port=CLAMAV_DAEMON_PORT, timeout=120)
    clamd.ping() # Test connection to the daemon
    print(f"[SERVER] Successfully connected to the ClamAV daemon at {CLAMAV_DAEMON_HOST}:{CLAMAV_DAEMON_PORT}.")
except pyclamd.ClamdNetworkSocketError as e:
    print(f"[SERVER ERROR] Could not connect to ClamAV daemon: {e}")
    print(f"[SERVER ERROR] Please ensure 'clamav-daemon' is running and configured for TCP on port {CLAMAV_DAEMON_PORT}.")
    print(f"[SERVER ERROR] Check /etc/clamav/clamd.conf for 'TCPSocket {CLAMAV_DAEMON_PORT}' and 'TCPAddr {CLAMAV_DAEMON_HOST}' (or '0.0.0.0').")
    print("[SERVER ERROR] You might need to restart 'clamav-daemon' after changing its config: sudo systemctl restart clamav-daemon")
    sys.exit(1) # Exit if cannot connect to ClamAV daemon, as scanning won't work
except Exception as e:
    print(f"[SERVER ERROR] An unexpected error occurred during ClamAV daemon connection: {e}")
    sys.exit(1)


# --- Start your custom scanning agent server ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows immediate reuse of the address/port
    server.bind((HOST, PORT))
    server.listen(1) # Listen for one incoming connection at a time
    print(f"[SERVER] ClamAV scanning agent listening for clients on port {PORT}...")

    while True: # Loop indefinitely to accept multiple client connections
        conn, addr = server.accept()
        with conn: # 'with' statement ensures the connection is closed when done
            print(f"[SERVER] Connection established with client: {addr}")

            tmp_path = None # Initialize tmp_path to None for cleanup in finally block
            try:
                # Receive file name length (4 bytes)
                name_len_bytes = conn.recv(4)
                if not name_len_bytes:
                    print("[SERVER] Client disconnected during file name length reception.")
                    conn.sendall(b"ERROR:ClientDisconnected")
                    continue # Go to next client connection
                name_len = int.from_bytes(name_len_bytes, 'big')
                
                # Receive file name
                file_name_bytes = conn.recv(name_len)
                if not file_name_bytes:
                    print("[SERVER] Client disconnected during file name reception.")
                    conn.sendall(b"ERROR:ClientDisconnected")
                    continue
                file_name = file_name_bytes.decode('utf-8')

                # Receive file size (8 bytes)
                file_size_bytes = conn.recv(8)
                if not file_size_bytes:
                    print("[SERVER] Client disconnected during file size reception.")
                    conn.sendall(b"ERROR:ClientDisconnected")
                    continue
                file_size = int.from_bytes(file_size_bytes, 'big')

                # Save to temporary file
                # Use tempfile.NamedTemporaryFile for safer temporary file handling
                with tempfile.NamedTemporaryFile(delete=False, dir=tempfile.gettempdir(), prefix="clamscan_server_", suffix=f"_{file_name}") as tmp_f:
                    tmp_path = tmp_f.name # Get the actual path of the temporary file
                    
                    bytes_read = 0
                    while bytes_read < file_size:
                        chunk = conn.recv(min(BUFFER_SIZE, file_size - bytes_read))
                        if not chunk:
                            print("[SERVER] Client disconnected unexpectedly during file transfer.")
                            break # Exit loop if client disconnects mid-transfer
                        tmp_f.write(chunk)
                        bytes_read += len(chunk)
                
                print(f"[SERVER] File '{file_name}' ({file_size} bytes) received and saved to {tmp_path}")
                
                # Set permissions only on non-Windows systems
                if not sys.platform.startswith('win'):
                    os.chmod(tmp_path, 0o644) # Ensure the file is readable by others (including clamav user)
                    print(f"[SERVER] Set permissions for {tmp_path} to 0o644.")
                
                result_string = "SCAN_ERROR:UnknownIssue" # Default error state
                try:
                    # --- Perform the actual scan using the pre-initialized clamd object ---
                    CLAMSCAN_PATH = ''
                    if sys.platform.startswith('win'):
                        CLAMSCAN_PATH = r"C:\\Program Files\\ClamAV\\clamscan.exe"  # Adjust path for Windows
                    elif sys.platform.startswith('linux'):
                        CLAMSCAN_PATH = '/usr/bin/clamscan'  # Adjust path for Linux
                    else:
                        print(f"[SERVER ERROR] Unsupported operating system: {sys.platform}")
                        sys.exit(1)
                    # --- Initial check: Ensure clamscan executable exists and is executable ---
                    if not os.path.exists(CLAMSCAN_PATH):
                        print(f"[SERVER ERROR] Clamscan executable not found at '{CLAMSCAN_PATH}'.")
                        print("[SERVER ERROR] Please ensure ClamAV is installed and the path is correct for your OS.")
                        sys.exit(1)
                    if not os.access(CLAMSCAN_PATH, os.X_OK): # os.X_OK checks for executable permission
                        print(f"[SERVER ERROR] Clamscan executable at '{CLAMSCAN_PATH}' is not executable.")
                        print(f"[SERVER ERROR] On Linux, try: sudo chmod +x {CLAMSCAN_PATH}")
                        sys.exit(1)

                    result = subprocess.run([
                        CLAMSCAN_PATH,
                        "--no-summary",
                        "--quiet", 
                        "--infected",
                        "--max-filesize=100M", 
                        "--max-scansize=100M", 
                        tmp_path
                    ], capture_output=True, text=True, timeout = 60)
                    if result.returncode == 1:
                        result_string = "INFECTED"
                    elif result.returncode == 0:
                        result_string = "OK"
                    else:
                        print(f"ClamAV error (code {result.returncode})")
                        conn.sendall(b"ERROR")

                except pyclamd.ClamdError as e:
                    print(f"[SERVER ERROR] ClamAV scan failed: {e}")
                    result_string = f"SCAN_ERROR:ClamAVFailed_{e}"
                except Exception as e:
                    print(f"[SERVER ERROR] An unexpected error occurred during scan: {e}")
                    result_string = f"SCAN_ERROR:InternalServerIssue_{e}"
                finally:
                    # Ensure temporary file is deleted after scanning
                    if tmp_path and os.path.exists(tmp_path):
                        os.remove(tmp_path)
                        print(f"[SERVER] Cleaned up temporary file: {tmp_path}")

                print(f"[SERVER] Sending scan result to client: '{result_string}'")
                conn.sendall(result_string.encode('utf-8'))

            except socket.error as se:
                print(f"[SERVER ERROR] Socket error during client connection handling: {se}")
                # Attempt to clean up temp file even on socket error
                if tmp_path and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception as e:
                print(f"[SERVER ERROR] An unexpected error occurred while handling client: {e}")
                # Attempt to clean up temp file even on general error
                if tmp_path and os.path.exists(tmp_path):
                    os.remove(tmp_path)