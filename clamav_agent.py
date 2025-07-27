import socket
import tempfile
import os

import sys
import subprocess

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12067      # Port for FTP client to connect
BUFFER_SIZE = 4096



def get_clamscan_path():
    """Return the path to clamscan based on OS."""
    if sys.platform.startswith('win'):
        return r"C:\\Program Files\\ClamAV\\clamscan.exe"
    elif sys.platform.startswith('linux'):
        return '/usr/bin/clamscan'
    else:
        print(f"[SERVER ERROR] Unsupported OS: {sys.platform}")
        sys.exit(1)

def scan_with_clamscan(file_path):
    """Scan file with clamscan subprocess and return result string."""
    clamscan_path = get_clamscan_path()
    if not os.path.exists(clamscan_path):
        print(f"[SERVER ERROR] Clamscan not found at '{clamscan_path}'.")
        sys.exit(1)
    if not os.access(clamscan_path, os.X_OK):
        print(f"[SERVER ERROR] Clamscan at '{clamscan_path}' is not executable.")
        sys.exit(1)
    try:
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
        if result.returncode == 1:
            return "INFECTED"
        elif result.returncode == 0:
            return "OK"
        else:
            print(f"[SERVER ERROR] ClamAV error (code {result.returncode})")
            return "SCAN_ERROR:ClamAVError"
    except Exception as e:
        print(f"[SERVER ERROR] Exception during clamscan: {e}")
        return f"SCAN_ERROR:ClamAVException_{e}"

def handle_client(conn, addr):
    """Handle a single client connection."""
    print(f"[SERVER] Connection established with client: {addr}")
    tmp_path = None
    try:
        # Receive file name length (4 bytes)
        name_len_bytes = conn.recv(4)
        if not name_len_bytes:
            print("[SERVER] Client disconnected during file name length reception.")
            conn.sendall(b"ERROR:ClientDisconnected")
            return
        name_len = int.from_bytes(name_len_bytes, 'big')

        # Receive file name
        file_name_bytes = conn.recv(name_len)
        if not file_name_bytes:
            print("[SERVER] Client disconnected during file name reception.")
            conn.sendall(b"ERROR:ClientDisconnected")
            return
        file_name = file_name_bytes.decode('utf-8')

        # Receive file size (8 bytes)
        file_size_bytes = conn.recv(8)
        if not file_size_bytes:
            print("[SERVER] Client disconnected during file size reception.")
            conn.sendall(b"ERROR:ClientDisconnected")
            return
        file_size = int.from_bytes(file_size_bytes, 'big')

        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, dir=tempfile.gettempdir(),
                                         prefix="clamscan_server_", suffix=f"_{file_name}") as tmp_f:
            tmp_path = tmp_f.name
            bytes_read = 0
            while bytes_read < file_size:
                chunk = conn.recv(min(BUFFER_SIZE, file_size - bytes_read))
                if not chunk:
                    print("[SERVER] Client disconnected during file transfer.")
                    break
                tmp_f.write(chunk)
                bytes_read += len(chunk)

        print(f"[SERVER] File '{file_name}' ({file_size} bytes) saved to {tmp_path}")

        # Set permissions (Linux only)
        if not sys.platform.startswith('win'):
            os.chmod(tmp_path, 0o644)
            print(f"[SERVER] Set permissions for {tmp_path} to 0o644.")

        # Scan the file
        result_string = scan_with_clamscan(tmp_path)

        print(f"[SERVER] Sending scan result to client: '{result_string}'")
        conn.sendall(result_string.encode('utf-8'))

    except socket.error as se:
        print(f"[SERVER ERROR] Socket error: {se}")
    except Exception as e:
        print(f"[SERVER ERROR] Unexpected error: {e}")
    finally:
        # Always clean up temp file
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
            print(f"[SERVER] Cleaned up temporary file: {tmp_path}")

# --- Main server loop ---
if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[SERVER] ClamAV scanning agent listening for clients on port {PORT}...")

        while True:
            conn, addr = server.accept()
            with conn:
                handle_client(conn, addr)
