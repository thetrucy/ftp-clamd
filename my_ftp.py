# my_ftp.py
# A from-scratch implementation of an FTP client library. It handles the low-level
# details of the FTP protocol.
# Now supports:
# - Both Passive (default) and Active data transfer modes.
# - Progress tracking via callbacks for uploads and downloads.
# - Custom exceptions for clear error handling.

import socket
import os
import re

# --- Custom Exceptions for Clearer Error Handling ---
class FTPError(Exception):
    """Base class for exceptions in this module."""
    pass

class FTPConnectError(FTPError):
    """For connection-related errors."""
    pass

class FTPPermError(FTPError):
    """For permanent errors (5xx FTP codes)."""
    pass

class FTPTempError(FTPError):
    """For temporary errors (4xx FTP codes)."""
    pass

class FTPClient:
    def __init__(self, buffer_size=4096, timeout=10):
        self.control_sock = None
        self.data_sock = None
        self.passive_mode = True # Default to Passive mode.
        self.binary_mode = True
        self.buffer_size = buffer_size
        self.timeout = timeout
        self.welcome_message = ""
        # Socket for listening in Active Mode.
        self.active_server_sock = None

    def connect(self, host, port=21):
        """Open control connection to FTP server."""
        try:
            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_sock.settimeout(self.timeout)
            self.control_sock.connect((host, port))
            # The first message is the welcome message
            self.welcome_message = self._get_response()
        except socket.gaierror:
            raise FTPConnectError(f"Hostname '{host}' could not be resolved.")
        except ConnectionRefusedError:
            raise FTPConnectError(f"Connection refused by server at {host}:{port}.")
        except Exception as e:
            raise FTPConnectError(f"Failed to connect: {e}")

    def getwelcome(self):
        """Return the server's welcome message."""
        return self.welcome_message

    def _send_command(self, cmd):
        """Send a command over control connection."""
        if not self.control_sock:
            raise FTPConnectError("Not connected to any FTP server.")
        data = cmd + '\r\n'
        self.control_sock.sendall(data.encode('utf-8'))

    def _get_response(self):
        """Read response lines until a complete reply code."""
        reply = ""
        while True:
            try:
                chunk = self.control_sock.recv(self.buffer_size).decode('utf-8')
                if not chunk:
                    raise FTPConnectError("Control connection closed unexpectedly.")
                reply += chunk
                # Check if last line is final of a multi-line response
                # A complete FTP response ends with 'DDD ' where D is a digit.
                if len(reply) >= 4 and reply[-1] == '\n' and re.search(r'^\d{3} ', reply.splitlines()[-1]):
                    break
            except socket.timeout:
                raise FTPConnectError("Timeout waiting for server response.")
        status_code = int(reply[:3])
        if status_code >= 500:
            raise FTPPermError(reply.strip())
        if status_code >= 400:
            raise FTPTempError(reply.strip())  
        return reply.strip()

    def login(self, user, password):
        """Send USER and PASS commands."""
        self._send_command(f"USER {user}")
        self._get_response() # Server asks for password
        self._send_command(f"PASS {password}")
        resp = self._get_response() # Final login response
        return resp

    def enter_active_mode(self):
        """
        Initializes a listening socket on the client side for Active Mode
        and sends the PORT command to the server.
        """
        self.active_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind to the same IP as the control connection, on a random free port (port 0).
        self.active_server_sock.bind((self.control_sock.getsockname()[0], 0))
        self.active_server_sock.listen(1)

        host, port = self.active_server_sock.getsockname()

        host_parts = host.split('.')
        # Divide the port into high and low bytes for the PORT command.
        port_high, port_low = divmod(port, 256)

        port_cmd = f"PORT {','.join(host_parts)},{port_high},{port_low}"
        self._send_command(port_cmd)
        self._get_response()

    def enter_passive_mode(self):
        """Switch to passive mode and open data socket."""
        self._send_command('PASV')
        resp = self._get_response()
        # Parse the host and port from the server's PASV response.
        match = re.search(r'\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)', resp)
        if not match:
            raise FTPError(f"Failed to parse PASV response: {resp}")
        
        host_parts = match.group(1).split(',')
        p1, p2 = int(match.group(2)), int(match.group(3))

        data_host = '.'.join(host_parts)
        data_port = (p1 * 256) + p2
        self.data_sock = socket.create_connection((data_host, data_port), timeout=self.timeout)

    def set_pasv(self, value):
        """Enable or disable passive mode."""
        if not isinstance(value, bool):
            raise TypeError("Passive mode value must be a boolean (True or False)")
        self.passive_mode = value

    def set_binary_mode(self, binary: bool): # To set global transfer mode
        """Sets the global transfer mode (binary or ASCII) for subsequent operations by sending the TYPE command."""
        if not self.control_sock:
            raise FTPConnectError("Not connected to any FTP server.")
        self.binary_mode = binary
        # It's good practice to immediately tell the server the type
        self._send_command(f"TYPE {'I' if self.binary_mode else 'A'}")
        self._get_response()
        print(f"Transfer mode set to: {'BINARY' if self.binary_mode else 'ASCII'} on server.")
   
    def nlst(self, path=''):
        """List names using NLST, supporting both Active and Passive modes."""
        # Step 1: Establish the data connection based on the current mode.
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()

        # Step 2: Send the NLST command.
        self._send_command(f'NLST {path}')
        resp = self._get_response() # Initial response (e.g., "150 Here comes the directory listing.")

        # Step 3: In Active mode, accept the incoming connection from the server.
        if not self.passive_mode:
            self.data_sock, _ = self.active_server_sock.accept()
            self.active_server_sock.close()
            self.active_server_sock = None

        # Step 4: Receive all data from the data socket.
        data = b''
        while True:
            chunk = self.data_sock.recv(self.buffer_size)
            if not chunk:
                break
            data += chunk
        self.data_sock.close()

        # Step 5: Get the final confirmation from the server.
        self._get_response() # Final response (e.g., "226 Directory send OK.")
        
        # Decode and split into a list, filtering out empty lines
        return [line for line in data.decode('utf-8').splitlines() if line.strip()]

    def cwd(self, dirpath):
        """Change working directory."""
        self._send_command(f'CWD {dirpath}')
        return self._get_response()

    def pwd(self):
        """Get current working directory, parsing the response."""
        self._send_command('PWD')
        resp = self._get_response()
        # Typical response: 257 "/path/to/dir" is the current directory.
        match = re.search(r'"(.*?)"', resp)
        if match:
            return match.group(1)
        return "Unknown" # Fallback

    def retr(self, remote_file, local_path, binary=True, callback = None):
        """Download remote_file to local_path (RETR command)."""
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()
        
        self._send_command(f"TYPE {'I' if binary else 'A'}")
        self._get_response()

        self._send_command(f'RETR {remote_file}')
        self._get_response()

        # Accept connection if in active mode
        if not self.passive_mode:
            self.data_sock, _ = self.active_server_sock.accept()
            self.active_server_sock.close()
            self.active_server_sock = None

        # Read from the data socket and write to the local file.
        with open(local_path, 'wb' if binary else 'w', encoding=None if binary else 'utf-8') as f:
            while True:
                chunk = self.data_sock.recv(self.buffer_size)
                if not chunk:
                    break
                f.write(chunk)
                # If a callback is provided, call it with the chunk of data.
                if callback: callback(chunk) # update progress bar
        self.data_sock.close()
        return self._get_response()

    def stor(self, local_path, remote_path=None, binary=True, callback = None):
        """Upload local_file to server as remote_path (or basename if not specified) (STOR command)."""
        filename = os.path.basename(local_path) if remote_path is None else remote_path
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()

        self._send_command(f"TYPE {'I' if binary else 'A'}")
        self._get_response()

        self._send_command(f'STOR {filename}')
        self._get_response()

        # Accept connection if in active mode
        if not self.passive_mode:
            self.data_sock, _ = self.active_server_sock.accept()
            self.active_server_sock.close()
            self.active_server_sock = None
        
        # Read the local file in chunks and send them over the data socket.
        with open(local_path, 'rb' if binary else 'r', encoding=None if binary else 'utf-8') as f:
            while True:
                chunk = f.read(self.buffer_size)
                if not chunk:
                    break
                # Ensure data is bytes before sending (for text mode).
                data_to_send = chunk if binary else chunk.encode('utf-8')
                self.data_sock.sendall(data_to_send)
                # If a callback is provided, call it to update progress.
                if callback: callback(data_to_send) # update progress bar
        self.data_sock.close()
        return self._get_response()
    
    def mkd(self, dirname):
        """Creates a directory."""
        self._send_command(f'MKD {dirname}')
        return self._get_response()

    def rmd(self, dirname):
        """Removes a directory."""
        self._send_command(f'RMD {dirname}')
        return self._get_response()

    def delete(self, filename):
        """Deletes a file."""
        self._send_command(f'DELE {filename}')
        return self._get_response()

    def rename(self, old_name, new_name):
        """Renames a file."""
        self._send_command(f'RNFR {old_name}')
        self._get_response()
        self._send_command(f'RNTO {new_name}')
        return self._get_response()

    def voidcmd(self, cmd):
        """Send a command and expect a success reply."""
        self._send_command(cmd)
        return self._get_response()
    
    def noop(self):
        self._send_command('NOOP')
        return self._get_response()

    def quit(self):
        """Send QUIT command and close connection."""
        try:
            self._send_command('QUIT')
            self._get_response()
        finally:
            if self.control_sock:
                self.control_sock.close()
                self.control_sock = None
    def size(self, filename):
        """Get the size of a file on the server using the SIZE command."""
        self._send_command(f'SIZE {filename}')
        resp = self._get_response()
        # The standard success response is "213 <size_in_bytes>".
        if resp.startswith('213'):
            return int(resp.split()[1])
        return 0