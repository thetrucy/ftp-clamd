# ftp_client.py
# This script is a command-line FTP client with a key security feature:
# it integrates with a ClamAV agent to scan files for viruses before
# allowing them to be uploaded.

import os
import socket
import shlex
import sys
import time
import threading

# Import the custom FTP logic and its exceptions.
from my_ftp import FTPClient as MyFTPClient, FTPError, FTPConnectError, FTPPermError, FTPTempError

# --- Global Configuration for the ClamAV scanning agent ---
CLAMAV_AGENT_HOST = '127.0.0.1' # Assumes the agent is running on the same machine.
CLAMAV_AGENT_PORT = 12067
BUFFER_SIZE = 4096

# --- Standardized Scan Results ---
# These constants help avoid typos and make the code easier to read.
SCAN_RESULT_CLEAN = "OK"
SCAN_RESULT_INFECTED_PREFIX = "INFECTED:"
SCAN_RESULT_ERROR = "ERROR"
SCAN_RESULT_SCAN_ERROR_PREFIX = "SCAN_ERROR:"


class FTPClient:
    """The main class that encapsulates all FTP client functionality."""
    def __init__(self):
        """Initializes the FTP client's state."""
        self.ftp = MyFTPClient()  # The low-level FTP implementation.
        self.connected = False    # Tracks connection status.
        self.current_dir = ""     # Caches the current remote directory.
        self.prompt_enabled = True # Toggles confirmation prompts for mget/mput.
        self.transfer_type = 'binary' # Default transfer mode.
        self.clamav_connected = False
        self.transfer_in_progress = False

    # --- Connection Management ---
    def connect_ftp(self, host, username, password, port=21):
        """Connects to an FTP server and logs in."""
        try:
            self.ftp.connect(host, port)
            welcome = self.ftp.getwelcome()
            print(f"✅ {welcome}")
            
            # Authenticate with the server.
            self.ftp.login(username, password)
            print(f"✅ Successfully connected to {host}.")
            
            self.connected = True
            self.current_dir = self.ftp.pwd()
            print(f"📍 Current directory: {self.current_dir}")
            return True
            
        except (FTPConnectError, FTPPermError, FTPTempError) as e:
            print(f"❌ Connection failed: {e}")
            self.connected = False
            return False
        except Exception as e:
            print(f"❌ An unexpected error occurred during FTP connection: {e}")
            self.connected = False
            return False

    def disconnect_ftp(self):
        """Gracefully disconnects from the FTP server using the QUIT command."""
        if self.ftp and self.connected:
            try:
                self.ftp.quit()
                print("👋 Disconnected from server.")
            except FTPError as e:
                print(f"❌ Error while disconnecting: {e}")
            finally:
                self.connected = False
        else:
            print("⚠️ Not connected to any FTP server.")

    @staticmethod
    def show_progress_bar(current, total, prefix="Progress", length=40):
        """Display a simple progress bar."""
        if total <= 0:
            percent = 100
            print(f'\r{prefix}: {current} bytes downloaded...', end="", flush=True)
            return
        
        percent = min(100.0, (current / total) * 100)
        display_current = min(current, total)
        filled_length = int(length * display_current // total)
        bar = '█' * filled_length + '-' * (length - filled_length)
        
        print(f'\r{prefix}: |{bar}| {percent:.1f}% ({current}/{total} bytes)', end="", flush=True)
        
        if current >= total:
            print()

    # --- ClamAV Integration ---
    def scan_file_with_clamav(self, file_path):
        """
        Connects to the ClamAV agent, sends a file for scanning, and
        returns the result from the agent.
        """
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return SCAN_RESULT_ERROR
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        try:
            # Establish a new connection to the ClamAV agent.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((CLAMAV_AGENT_HOST, CLAMAV_AGENT_PORT))
                print(f"🔬 Connected to ClamAV Agent at {CLAMAV_AGENT_HOST}:{CLAMAV_AGENT_PORT}")

                # --- Follow the ClamAV Agent Protocol ---
                # 1. Send file name length (4 bytes) and name.
                s.sendall(len(file_name).to_bytes(4, byteorder='big'))
                s.sendall(file_name.encode('utf-8'))
                
                # 2. Send file size (8 bytes).
                s.sendall(file_size.to_bytes(8, byteorder='big'))

                # 3. Stream the file content in chunks.
                with open(file_path, "rb") as f:
                    while True:
                        data = f.read(BUFFER_SIZE)
                        if not data:
                            break
                        s.sendall(data)
                        sent_bytes += len(data)
                        #FTPClient.show_progress_bar(sent_bytes, file_size, "Scan")
                
                # 4. Receive and interpret the scan result.
                result = s.recv(1024).decode('utf-8').strip()
                print(f"🔍 Scan result for {file_name}: {result}")
                
                # Return a standardized result based on the agent's response.
                if result.startswith(SCAN_RESULT_INFECTED_PREFIX):
                    print(f"🛑 FILE INFECTED! Virus: {result[len(SCAN_RESULT_INFECTED_PREFIX):]}")
                    return SCAN_RESULT_INFECTED_PREFIX
                elif result == SCAN_RESULT_CLEAN:
                    print(f"✅ File is CLEAN.")
                    return SCAN_RESULT_CLEAN
                elif result.startswith(SCAN_RESULT_SCAN_ERROR_PREFIX):
                    print(f"❌ Scan error: {result[len(SCAN_RESULT_SCAN_ERROR_PREFIX):]}")
                    return SCAN_RESULT_ERROR
                else:
                    print(f"❌ Unknown scan result: {result}")
                    return SCAN_RESULT_ERROR
                    
        except ConnectionRefusedError:
            print(f"🚫 Connection to ClamAV agent at {CLAMAV_AGENT_HOST}:{CLAMAV_AGENT_PORT} refused.")
            return SCAN_RESULT_ERROR
        except Exception as e:
            print(f"❌ Error communicating with ClamAV Agent: {e}")
            return SCAN_RESULT_ERROR

    def set_clamav_agent_config(self):
        """Allows the user to change the ClamAV agent's host and port at runtime."""
        global CLAMAV_AGENT_HOST, CLAMAV_AGENT_PORT
        print("🛠️ Configure ClamAV agent (leave blank to keep current values):")
        
        new_host = input(f"Enter ClamAV Agent Host (current: {CLAMAV_AGENT_HOST}): ").strip()
        new_port = input(f"Enter ClamAV Agent Port (current: {CLAMAV_AGENT_PORT}): ").strip()
        
        if new_host:
            CLAMAV_AGENT_HOST = new_host
        try:
            if new_port:
                CLAMAV_AGENT_PORT = int(new_port)
        except ValueError:
            print("❌ Invalid port number. Port must be an integer.")
            return
            
        print(f"✅ ClamAV Agent configured to: {CLAMAV_AGENT_HOST}:{CLAMAV_AGENT_PORT}")


    # --- File Operations ---
    def list_files(self):
        """Lists files in the current remote directory."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return
            
        try:
            print("📂 Listing files:")
            files = self.ftp.nlst()
            if not files:
                print("⚠️ No files found in this directory.")
            for f in files:
                print(f"   📄 {f}")
        except FTPError as e:
            print(f"❌ Error listing directory: {e}")

    def change_directory(self, remote_dir):
        """Changes the current directory on the FTP server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return
            
        try:
            self.ftp.cwd(remote_dir)
            self.current_dir = self.ftp.pwd()
            print(f"📁 Changed to directory: {self.current_dir}")
        except FTPError as e:
            print(f"❌ Failed to change directory: {e}")

    def print_working_directory(self):
        """Shows the current working directory on the server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return
            
        try:
            print(f"📍 Current directory: {self.ftp.pwd()}")
        except FTPError as e:
            print(f"❌ Error getting current directory: {e}")

    def local_change_directory(self, local_dir):
        """Changes the current directory on the local machine."""
        try:
            os.chdir(local_dir)
            print(f"📂 Local directory changed to: {os.getcwd()}")
        except FileNotFoundError:
            print(f"❌ Local directory not found: {local_dir}")
        except Exception as e:
            print(f"❌ Failed to change local directory: {e}")

    def make_directory(self, remote_dir_path):
        """Creates a new directory on the FTP server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return False
        if not remote_dir_path:
            print("Usage: mkdir <remote_directory_path>")
            return False
            
        try:
            self.ftp.mkd(remote_dir_path)
            print(f"📁 Directory '{remote_dir_path}' created on server.")
            return True
        except FTPError as e:
            print(f"❌ Error creating directory '{remote_dir_path}': {e}")
            return False

    def remove_directory(self, remote_dir_path):
        """Removes a directory from the FTP server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return False
        if not remote_dir_path:
            print("Usage: rmdir <remote_directory_path>")
            return False
            
        try:
            self.ftp.rmd(remote_dir_path)
            print(f"🗑️ Directory '{remote_dir_path}' removed from server.")
            return True
        except FTPError as e:
            print(f"❌ Error removing directory '{remote_dir_path}': {e}")
            return False

    def delete_file(self, remote_file_path):
        """Deletes a file from the FTP server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return False
        if not remote_file_path:
            print("Usage: delete <remote_file_path>")
            return False
            
        try:
            self.ftp.delete(remote_file_path)
            print(f"🗑️ File '{remote_file_path}' deleted from server.")
            return True
        except FTPError as e:
            print(f"❌ Error deleting file '{remote_file_path}': {e}")
            return False

    def rename_item(self, from_path, to_path=None):
        """Renames a file or directory on the FTP server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return False
        if not from_path:
            print("Usage: rename <old_path> [new_path]")
            return False
            
        # Prompt for the new name if not provided.
        if not to_path:
            to_path = input("✏️ New file name (include extension): ").strip()
            
        try:
            self.ftp.rename(from_path, to_path)
            print(f"📄 Renamed '{from_path}' to '{to_path}' on server.")
            return True
        except FTPError as e:
            print(f"❌ Error renaming '{from_path}' to '{to_path}': {e}")
            return False

    class ProgressCallback:
        """Callback class to track upload/download progress."""
        def __init__(self, file_size, operation="Transfer"):
            self.file_size = file_size
            self.transferred = 0
            self.operation = operation
            
        def __call__(self, data):
            self.transferred += len(data)
            FTPClient.show_progress_bar(self.transferred, self.file_size, self.operation)

    # --- Transfer Operations ---
    def upload_file(self, local_path, remote_path=None):
        """
        Uploads a single file, but **scans it with ClamAV first**.
        If the scan fails or finds a virus, the upload is cancelled.
        """
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return False
            
        local_path = local_path.strip('"')
        if not os.path.exists(local_path):
            print(f"❌ File '{local_path}' not found")
            return False

        # --- CRITICAL STEP: Scan the file before proceeding with the upload. ---
        scan_result = self.scan_file_with_clamav(local_path)
        if scan_result != SCAN_RESULT_CLEAN:
            print("🛑 Upload cancelled due to scan result.")
            return False

        # If the file is clean, proceed with the FTP upload.
        try:
            if not remote_path:
                remote_path = os.path.basename(local_path)
            file_size = os.path.getsize(local_path)
            # Khởi tạo callback để theo dõi tiến trình
            progress_callback = self.ProgressCallback(file_size, "Upload")

            print(f"📤 Uploading '{local_path}' to server as '{remote_path}'...")
            self.ftp.stor(local_path, remote_path, binary=(self.transfer_type == 'binary')
                          , callback = progress_callback)

            print("✅ Upload successful.")
            return True
            
        except FTPError as e:
            print(f"❌ Upload error: {e}")
            return False

    def download_file(self, remote_path, local_path=None):
        """Downloads a single file from the server."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return False
            
        try:
            if not local_path:
                local_path = os.path.basename(remote_path)
                
            file_size = self.ftp.size(remote_path)

            progress_callback = self.ProgressCallback(file_size, "Download")

            print(f"⬇️ Downloading '{remote_path}' from server...")            
            self.ftp.retr(remote_path, local_path, binary=(self.transfer_type == 'binary')
                          , callback = progress_callback)
                    
            print(f"✅ Downloaded: {remote_path} to {local_path}")
            return True
            
        except FTPError as e:
            print(f"\n❌ Download failed: {e}")
            return False

    def upload_files(self, local_dir=None):
        """
        Implements 'mput' functionality to upload multiple files from a local
        directory, potentially recursively.
        """
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return
            
        print("📤 Multi-file upload")
        if not local_dir:
            local_dir = input("📁 Enter local folder to upload from (or drag and drop): ").strip().strip('"')
            
        if not local_dir:
            local_dir = '.'
            
        if not os.path.isdir(local_dir):
            print(f"❌ Folder not found or invalid: {local_dir}")
            return

        # Ask the user if they want to upload subdirectories too.
        recursive = input("⬆️ Recursively upload sub-directories? [Y/N]: ").strip().lower() == 'y'
        
        original_server_dir = self.ftp.pwd()
        success_count = 0
        fail_count = 0

        # Build a list of all files that need to be uploaded.
        files_to_upload = []
        if recursive:
            for dirpath, _, filenames in os.walk(local_dir):
                for f in filenames:
                    files_to_upload.append(os.path.join(dirpath, f))
        else:
            for f in os.listdir(local_dir):
                full_path = os.path.join(local_dir, f)
                if os.path.isfile(full_path):
                    files_to_upload.append(full_path)

        # Iterate through the list and upload each file.
        for local_full_path in files_to_upload:
            # If prompting is enabled, ask for confirmation for each file.
            if self.prompt_enabled:
                confirm = input(f"⬆️ Upload {local_full_path}? [Y/N]: ").strip().lower()
                if confirm != 'y':
                    print(f"⏭️ Skipped: {local_full_path}")
                    continue

            try:
                # --- Handle subdirectory creation on the remote server ---
                relative_path = os.path.relpath(local_full_path, local_dir)
                remote_dir_part = os.path.dirname(relative_path)
                remote_filename = os.path.basename(relative_path)

                if remote_dir_part:
                    remote_dir_part_unix = remote_dir_part.replace('\\', '/')
                    dir_components = remote_dir_part_unix.split('/')
                    
                    # Create each directory component if it doesn't exist.
                    for component in dir_components:
                        try:
                            self.ftp.cwd(component)
                        except Exception:
                            try:
                                self.ftp.mkd(component)
                                self.ftp.cwd(component)
                            except Exception as e:
                                print(f"❌ Failed to create/access remote directory '{component}': {e}")
                                raise e # Stop processing this file

                print(f"🌍 Server CWD is now: {self.ftp.pwd()}")
                # Use the existing upload_file method, which includes the virus scan.
                if self.upload_file(local_full_path, remote_filename):
                    success_count += 1
                else:
                    fail_count += 1

            except Exception as e:
                print(f"❌ Failed to upload {local_full_path}: {e}")
                fail_count += 1
            finally:
                # IMPORTANT: Always return to the original directory on the server.
                try:
                    self.ftp.cwd(original_server_dir)
                except Exception as e:
                    print(f"⚠️ Warning: Failed to return to original server directory: {e}")

        print(f"\n✅ Upload finished. Success: {success_count}, Failed: {fail_count}")

    def download_directory_recursively(self, remote_dir, local_dir):
        """A helper function to recursively download a directory's contents."""
        try:
            # Create the local directory if it doesn't exist.
            os.makedirs(local_dir, exist_ok=True)
            print(f"📂 Syncing remote '{remote_dir}' to local '{os.path.abspath(local_dir)}'")
            
            original_server_dir = self.ftp.pwd()
            
            try:
                self.ftp.cwd(remote_dir)
            except Exception as e:
                print(f"❌ Failed to enter remote directory '{remote_dir}': {e}")
                return
            
            print(f"📁 Processing server directory: {self.ftp.pwd()}")
            items = self.ftp.nlst()

            for item_name in items:
                try:
                    # A simple way to check if an item is a directory is to try changing into it.
                    self.ftp.cwd(item_name)
                    self.ftp.cwd('..')
                    # If the above worked, it's a directory. Recurse into it.
                    new_local_dir = os.path.join(local_dir, item_name)
                    self.download_directory_recursively(item_name, new_local_dir)
                except FTPPermError:
                    # If we couldn't CWD, it's a file. Download it.
                    local_file_path = os.path.join(local_dir, item_name)
                    self.download_file(item_name, local_file_path)

            # Go back up to the parent directory on the server.
            self.ftp.cwd(original_server_dir)

        except (FTPPermError, FTPError) as e:
            print(f"❌ Error processing directory '{remote_dir}': {e}")
            try:
                # Attempt to return to original directory even on error.
                self.ftp.cwd(original_server_dir)
            except FTPError:
                pass

    def download_files(self, remote_target):
        """
        Implements 'mget' functionality to download a remote directory recursively.
        """
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return
            
        print(f"📥 Multi-file/Directory download for: '{remote_target}'")
        
        # Ask user where to save the files locally.
        local_destination = input(f"📁 Enter local folder to save into (default: ./{remote_target}): ").strip()
        if not local_destination:
            local_destination = remote_target.split('/')[-1]

        original_server_dir = self.ftp.pwd()
        print(f"Files will be saved to '{os.path.abspath(local_destination)}'")

        success = True

        try:
            self.download_directory_recursively(remote_target, local_destination)
        except Exception as e:
            print(f"❌ A critical error occurred during download: {e}")
            success = False
        finally:
            # Always try to return to the starting directory.
            try:
                self.ftp.cwd(original_server_dir)
            except FTPError as e:
                print(f"⚠️ Warning: Could not return to original server directory '{original_server_dir}': {e}")
                success = False
                
        if success:
            print("\n✅ Download finished.")
        else:
            print("\n⚠️ Download completed with errors.")

    # --- Settings and Configuration ---
    def toggle_passive_mode(self, mode=None):
        """Toggles or sets the FTP passive mode."""
        if not self.connected:
            print("❌ Not connected to FTP server.")
            return
            
        if mode is None:
            # If no mode is specified, flip the current setting.
            self.ftp.set_pasv(not self.ftp.passive_mode)
        elif mode.lower() == 'on':
            self.ftp.set_pasv(True)
        elif mode.lower() == 'off':
            self.ftp.set_pasv(False)
        else:
            print("❓ Usage: passive <on/off>")
            return
            
        print(f"🌐 Passive mode {'ON' if self.ftp.passive_mode else 'OFF'}")

    def set_transfer_mode(self, mode):
        """Sets the file transfer mode to ASCII or binary."""
        if mode.lower() == 'binary':
            self.transfer_type = 'binary'
        elif mode.lower() == 'ascii':
            self.transfer_type = 'ascii'
        else:
            print("❓ Usage: ascii or binary")
            return
            
        print(f"🔄 Transfer mode set to {self.transfer_type}")
        
        # If connected, immediately send the TYPE command to the server.
        if self.connected:
            try:
                self.ftp.set_binary_mode(self.transfer_type == 'binary')
            except (AttributeError, FTPError):
                pass # The server will be notified before each transfer anyway.

    def toggle_prompt(self):
        """Toggles the confirmation prompt for multi-file operations (mget/mput)."""
        self.prompt_enabled = not self.prompt_enabled
        print(f"🔁 Prompting is now {'✅ ON' if self.prompt_enabled else '🚫 OFF'} for mget/mput operations.")

    def show_status(self):
        """Displays the current status of the FTP session."""
        if not self.connected:
            print("❌ Not connected to any FTP server.")
            return
            
        try:
            # Send a NOOP command to check if the connection is still alive.
            self.ftp.voidcmd("NOOP")
            print("✅ FTP connection is active.")
            print(f"📍 Current directory: {self.ftp.pwd()}")
            print(f"🔄 Transfer mode: {self.transfer_type}")
            print(f"🌐 Passive mode: {'ON' if self.ftp.passive_mode else 'OFF'}")
            print(f"🔁 Prompting: {'ON' if self.prompt_enabled else 'OFF'}")
            print(f"🔬 ClamAV Agent: {CLAMAV_AGENT_HOST}:{CLAMAV_AGENT_PORT}")
        except FTPError as e:
            print(f"❌ FTP connection is closed or broken: {e}")

    def show_help(self):
        """Displays a list of all available commands."""
        print(
            '--- File/Directory Commands ---\n'
            'ls                List files/folders on server\n'
            'cd <dir>          Change directory on server\n'
            'pwd               Show current server directory\n'
            'lcd <dir>         Change directory on local machine\n'
            'mkdir <dir>       Create folder on server\n'
            'rmdir <dir>       Delete folder on server\n'
            'delete <file>     Delete a file on server\n'
            'rename <file>     Rename a file on server\n'
            '--- Transfer Commands ---\n'
            'get <rem> [loc]   Download a single file (remote to local)\n'
            'put <loc>         Upload a single file (local to remote), scans first\n'
            'mget <rem_dir>    Download a full directory recursively\n'
            'mput [loc_dir]    Upload multiple files from a local directory\n'
            '--- Settings ---\n'
            'prompt            Toggle confirmation for mget/mput\n'
            'ascii/binary      Set file transfer mode\n'
            'passive <on/off>  Toggle passive FTP mode\n'
            'set_clamav_agent  Set ClamAV agent host and port\n'
            '--- General ---\n'
            'open <host> <port> <user> <pass>  Connect to FTP server\n'
            'close             Disconnect from FTP server\n'
            'status            Show current session status\n'
            'quit/bye          Exit the FTP client\n'
            'help/?            Show this help message\n'
        )

    # --- Command Handler ---
    def handle_command(self, command):
        """Parses and dispatches user commands to the appropriate methods."""
        if not command.strip():
            return True # Continue loop for empty command.
            
        try:
            # Use shlex to handle quoted arguments correctly (e.g., paths with spaces).
            parts = shlex.split(command)
        except ValueError as e:
            print(f"❌ Invalid command syntax: {e}")
            return True
            
        cmd = parts[0].lower()
        args = parts[1:]

        try:
            # This large block maps the command string to the corresponding class method.
            if cmd in ('quit', 'bye'):
                self.disconnect_ftp()
                print("👋 Exiting. Goodbye!")
                return False # Signal to exit the main loop.
                
            elif cmd == 'open':
                if len(args) < 4:
                    print("Usage: open <host> <port> <username> <password>")
                    return True
                host, port, username, password = args[0], int(args[1]), args[2], args[3]
                self.connect_ftp(host, username, password, port)
                
            elif cmd == 'close':
                self.disconnect_ftp()
                
            elif cmd == 'ls':
                self.list_files()
                
            elif cmd == 'cd':
                if args:
                    self.change_directory(args[0])
                else:
                    print("Usage: cd <directory>")
                    
            elif cmd == 'pwd':
                self.print_working_directory()
                
            elif cmd == 'lcd':
                if args:
                    self.local_change_directory(args[0])
                else:
                    print("Usage: lcd <directory>")
                    print(f"Current local directory: {os.getcwd()}")
                    
            elif cmd == 'mkdir':
                if args:
                    self.make_directory(args[0])
                else:
                    print("Usage: mkdir <directory>")
                    
            elif cmd == 'rmdir':
                if args:
                    self.remove_directory(args[0])
                else:
                    print("Usage: rmdir <directory>")
                    
            elif cmd == 'delete':
                if args:
                    self.delete_file(args[0])
                else:
                    print("Usage: delete <filename>")
                    
            elif cmd == 'rename':
                if len(args) >= 2:
                    self.rename_item(args[0], args[1])
                elif len(args) == 1:
                    self.rename_item(args[0])
                else:
                    print("Usage: rename <old_name> [new_name]")
                    
            elif cmd in ('get', 'recv'):
                if args:
                    local_path = args[1] if len(args) > 1 else None
                    self.download_file(args[0], local_path)
                else:
                    print("Usage: get <remote_filename> [local_filename]")
                    
            elif cmd == 'put':
                if args:
                    remote_path = args[1] if len(args) > 1 else None
                    self.upload_file(args[0], remote_path)
                else:
                    print("Usage: put <local_filename> [remote_filename]")
                    
            elif cmd == 'mget':
                if args:
                    self.download_files(args[0])
                else:
                    print("Usage: mget <remote_directory>")
                    
            elif cmd == 'mput':
                local_dir = args[0] if args else None
                self.upload_files(local_dir)
                
            elif cmd == 'prompt':
                self.toggle_prompt()
                
            elif cmd == 'ascii':
                self.set_transfer_mode('ascii')
                
            elif cmd == 'binary':
                self.set_transfer_mode('binary')
                
            elif cmd == 'passive':
                mode = args[0] if args else None
                self.toggle_passive_mode(mode)
                
            elif cmd == 'status':
                self.show_status()
                
            elif cmd == 'set_clamav_agent':
                self.set_clamav_agent_config()
                
            elif cmd in ('help', '?'):
                self.show_help()
                
            else:
                print(f"❓ Unknown command: {cmd}. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"❌ Error processing command '{cmd}': {e}")
            
        return True # Signal to continue the main loop.


def main():
    """The main entry point of the application. Runs the command loop."""
    client = FTPClient()
    print("🚀 FTP Client with ClamAV Integration 🚀")
    print("🧠 Type 'help' or '?' for available commands.")
    print("💡 Use 'open <host> <port> <username> <password>' to connect.")
    
    # The main REPL (Read-Eval-Print Loop).
    while True:
        try:
            # Create a dynamic prompt that shows the connection status and current directory.
            if client.connected:
                try:
                    current_dir = client.ftp.pwd()
                    prompt_str = f"ftp:{current_dir}> "
                except FTPError:
                    # If pwd fails, the connection might be broken.
                    prompt_str = "ftp:[disconnected]> "
            else:
                prompt_str = "ftp> "
                
            command = input(prompt_str).strip()
            # If handle_command returns False, it means the user typed 'quit' or 'bye'.
            if not client.handle_command(command):
                break
                
        except (KeyboardInterrupt, EOFError):
            # Handle Ctrl+C or Ctrl+D gracefully.
            print("\n👋 Interrupted. Closing connection.")
            client.disconnect_ftp()
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()