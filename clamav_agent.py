# clamav_agent.py
# This script acts as a standalone server that receives files over a socket,
# scans them using the ClamAV command-line tool (`clamscan`), and returns a
# simple result (OK, INFECTED, or ERROR).

import socket
import tempfile
import os
import sys
import subprocess

# --- Configuration ---
# Global settings for the server.
HOST = '0.0.0.0'  # Listen on all available network interfaces.
PORT = 12067      # The port this server will listen on.
BUFFER_SIZE = 4096 # Size of chunks for receiving file data.


def get_clamscan_path():
    """
    Determines the correct path to the `clamscan` executable based on the
    operating system (Windows or Linux).
    """
    if sys.platform.startswith('win'):
        # Standard installation path for ClamAV on Windows.
        return r"C:\\Program Files\\ClamAV\\clamscan.exe"
    elif sys.platform.startswith('linux'):
        # Standard path for clamscan on most Linux distributions.
        return '/usr/bin/clamscan'
    else:
        # Exit if the OS is not supported.
        print(f"[SERVER ERROR] Unsupported OS: {sys.platform}")
        sys.exit(1)

def scan_with_clamscan(file_path):
    """
    Scans a given file using the `clamscan` executable in a separate process.

    Returns a simple string indicating the scan result ('OK', 'INFECTED', 'SCAN_ERROR').
    """
    clamscan_path = get_clamscan_path()

    # Ensure the clamscan executable exists and is runnable.
    if not os.path.exists(clamscan_path):
        print(f"[SERVER ERROR] Clamscan not found at '{clamscan_path}'.")
        sys.exit(1)
    if not os.access(clamscan_path, os.X_OK):
        print(f"[SERVER ERROR] Clamscan at '{clamscan_path}' is not executable.")
        sys.exit(1)

    try:
        # Execute clamscan with arguments for clean, machine-readable output.
        # --stdout: Print result to standard output instead of the console.
        # --no-summary: Hides the summary statistics for cleaner output.
        # --infected: Only prints infected files.
        # --quiet: Suppress OK results.
        result = subprocess.run([
            clamscan_path,
            "--stdout",
            "--no-summary",
            "--quiet",
            "--infected",
            "--max-filesize=100M",
            "--max-scansize=100M",
            file_path
        ], capture_output=True, text=True, timeout=300)

        # Interpret the exit code from clamscan. This is the standard.
        # 0 = File is clean.
        # 1 = File is infected.
        # Other = An error occurred during the scan.
        if result.returncode == 1:
            return "INFECTED"
        elif result.returncode == 0:
            return "OK"
        else:
            print(f"[SERVER ERROR] ClamAV error (code {result.returncode})")
            return "SCAN_ERROR:ClamAVError"

    except Exception as e:
        # Catch any other exceptions, like a timeout.
        print(f"[SERVER ERROR] Exception during clamscan: {e}")
        return f"SCAN_ERROR:ClamAVException_{e}"

def handle_client(conn, addr):
    """
    Manages the entire communication with a single connected client.
    It follows a simple protocol to receive the file, scan it, and send a result.
    """
    print(f"[SERVER] Connection established with client: {addr}")
    tmp_path = None
    try:
        # --- Protocol Step 1: Receive file name ---
        # First 4 bytes tell us the length of the file name.
        name_len_bytes = conn.recv(4)
        if not name_len_bytes:
            print("[SERVER] Client disconnected during file name length reception.")
            conn.sendall(b"ERROR:ClientDisconnected")
            return
        name_len = int.from_bytes(name_len_bytes, 'big')

        # Receive the actual file name.
        file_name_bytes = conn.recv(name_len)
        if not file_name_bytes:
            print("[SERVER] Client disconnected during file name reception.")
            conn.sendall(b"ERROR:ClientDisconnected")
            return
        file_name = file_name_bytes.decode('utf-8')

        # --- Protocol Step 2: Receive file size ---
        # Next 8 bytes tell us the size of the file content.
        file_size_bytes = conn.recv(8)
        if not file_size_bytes:
            print("[SERVER] Client disconnected during file size reception.")
            conn.sendall(b"ERROR:ClientDisconnected")
            return
        file_size = int.from_bytes(file_size_bytes, 'big')

        # --- Protocol Step 3: Receive file content and save to a temporary file ---
        # Using a temporary file ensures it's stored safely and is cleaned up later.
        # `delete=False` is needed so we can get its path to pass to clamscan.
        with tempfile.NamedTemporaryFile(delete=False, dir=tempfile.gettempdir(),
                                         prefix="clamscan_server_", suffix=f"_{file_name}") as tmp_f:
            tmp_path = tmp_f.name
            bytes_read = 0
            # Read the file in chunks to handle large files without using too much memory.
            while bytes_read < file_size:
                chunk = conn.recv(min(BUFFER_SIZE, file_size - bytes_read))
                if not chunk:
                    print("[SERVER] Client disconnected during file transfer.")
                    break
                tmp_f.write(chunk)
                bytes_read += len(chunk)

        print(f"[SERVER] File '{file_name}' ({file_size} bytes) saved to {tmp_path}")

        # Set file permissions to be safe (Linux/macOS only).
        if not sys.platform.startswith('win'):
            os.chmod(tmp_path, 0o644)
            print(f"[SERVER] Set permissions for {tmp_path} to 0o644.")

        # --- Step 4: Scan the file ---
        result_string = scan_with_clamscan(tmp_path)

        # --- Step 5: Send the result back to the client ---
        print(f"[SERVER] Sending scan result to client: '{result_string}'")
        conn.sendall(result_string.encode('utf-8'))

    except socket.error as se:
        print(f"[SERVER ERROR] Socket error: {se}")
    except Exception as e:
        print(f"[SERVER ERROR] Unexpected error: {e}")
    finally:
        # --- Cleanup ---
        # Ensure the temporary file is deleted, even if errors occurred.
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
            print(f"[SERVER] Cleaned up temporary file: {tmp_path}")

# --- Main server loop ---
if __name__ == '__main__':
    # Set up the server socket to listen for incoming connections.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # This allows the server to restart quickly and reuse the same address.
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[SERVER] ClamAV scanning agent listening for clients on port {PORT}...")

        # Main loop to continuously accept new client connections.
        while True:
            conn, addr = server.accept()
            # Use a 'with' statement to ensure the client connection is automatically closed.
            with conn:
                handle_client(conn, addr)