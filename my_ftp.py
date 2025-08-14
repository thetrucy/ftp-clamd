# my_ftp.py
# A basic, from-scratch implementation of an FTP client. It handles the
# low-level details of the FTP protocol, including control connections,
# data connections (passive mode), and command/response handling.

import socket
import os
import re

# --- Custom Exceptions ---
# This makes error handling in the main client more specific and readable,
# allowing it to distinguish between a connection error and a permissions error.
class FTPError(Exception):
    """Base class for all exceptions in this module."""
    pass

class FTPConnectError(FTPError):
    """For errors related to establishing a connection."""
    pass

class FTPPermError(FTPError):
    """For permanent FTP errors (server replies with a 5xx code)."""
    pass

class FTPTempError(FTPError):
    """For temporary FTP errors (server replies with a 4xx code)."""
    pass

class FTPClient:
    """Handles the low-level FTP protocol communication."""
    def __init__(self, buffer_size=4096, timeout=10):
        """Initializes the FTP client's low-level state."""
        self.control_sock = None  # The socket for commands and responses.
        self.data_sock = None     # The socket for file transfers and listings.
        self.passive_mode = True  # Default to passive mode, which is more firewall-friendly.
        self.binary_mode = True   # Default to binary transfer mode.
        self.buffer_size = buffer_size
        self.timeout = timeout
        self.welcome_message = ""
        self.active_server_sock = None

    def connect(self, host, port=21):
        """Establishes the initial control connection to the FTP server."""
        try:
            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_sock.settimeout(self.timeout)
            self.control_sock.connect((host, port))
            # The first message from the server after connecting is the welcome message.
            self.welcome_message = self._get_response()
        except socket.gaierror:
            raise FTPConnectError(f"Hostname '{host}' could not be resolved.")
        except ConnectionRefusedError:
            raise FTPConnectError(f"Connection refused by server at {host}:{port}.")
        except Exception as e:
            raise FTPConnectError(f"Failed to connect: {e}")

    def getwelcome(self):
        """Returns the server's welcome message received upon connection."""
        return self.welcome_message

    def _send_command(self, cmd):
        """
        Sends a raw command string to the server over the control connection,
        appending the required '\\r\\n'.
        """
        if not self.control_sock:
            raise FTPConnectError("Not connected to any FTP server.")
        data = cmd + '\r\n'
        self.control_sock.sendall(data.encode('utf-8'))

    def _get_response(self):
        """
        Reads one or more lines from the server until a complete FTP response
        is received. It also checks the response code for errors.
        """
        reply = ""
        while True:
            try:
                chunk = self.control_sock.recv(self.buffer_size).decode('utf-8')
                if not chunk:
                    raise FTPConnectError("Control connection closed unexpectedly.")
                reply += chunk
                # A complete FTP response is detected when the last line starts with
                # a 3-digit code followed by a space. This handles multi-line responses.
                if len(reply) >= 4 and reply[-1] == '\n' and re.search(r'^\d{3} ', reply.splitlines()[-1]):
                    break
            except socket.timeout:
                raise FTPConnectError("Timeout waiting for server response.")
        
        # Check the status code and raise an appropriate exception on failure.
        status_code = int(reply[:3])
        if status_code >= 500:
            raise FTPPermError(reply.strip()) # 5xx codes are permanent errors.
        if status_code >= 400:
            raise FTPTempError(reply.strip()) # 4xx codes are temporary errors.
        return reply.strip()

    def login(self, user, password):
        """Authenticates with the server using USER and PASS commands."""
        self._send_command(f"USER {user}")
        self._get_response() # Server typically responds with '331 Please specify the password.'
        self._send_command(f"PASS {password}")
        resp = self._get_response() # Final login response (e.g., '230 Login successful.')
        return resp

    def enter_active_mode(self):
        """Create a listening socket and send PORT command for Active Mode."""
        self.active_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind vào IP của control connection và một cổng ngẫu nhiên (số 0)
        self.active_server_sock.bind((self.control_sock.getsockname()[0], 0))
        self.active_server_sock.listen(1)

        host, port = self.active_server_sock.getsockname()

        host_parts = host.split('.')
        port_high, port_low = divmod(port, 256) # Chia cổng thành 2 byte

        port_cmd = f"PORT {','.join(host_parts)},{port_high},{port_low}"
        self._send_command(port_cmd)
        self._get_response()

    def enter_passive_mode(self):
        """
        Sends the PASV command and establishes the data connection based on
        the server's response.
        """
        self._send_command('PASV')
        resp = self._get_response()
        
        # The server responds with a tuple like (h1,h2,h3,h4,p1,p2). We need to parse it.
        match = re.search(r'\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)', resp)
        if not match:
            raise FTPError(f"Failed to parse PASV response: {resp}")
        
        host_parts = match.group(1).split(',')
        p1, p2 = int(match.group(2)), int(match.group(3))

        # Reconstruct the IP address and calculate the port.
        data_host = '.'.join(host_parts)
        # The data port is calculated as (p1 * 256) + p2.
        data_port = (p1 * 256) + p2
        
        # Connect to the host and port provided by the server.
        self.data_sock = socket.create_connection((data_host, data_port), timeout=self.timeout)

    def set_pasv(self, value):
        """Enable or disable passive mode for future data transfers."""
        if not isinstance(value, bool):
            raise TypeError("Passive mode value must be a boolean (True or False)")
        self.passive_mode = value

    def set_binary_mode(self, binary: bool):
        """Sets the transfer mode (binary or ASCII) by sending the TYPE command."""
        if not self.control_sock:
            raise FTPConnectError("Not connected to any FTP server.")
        self.binary_mode = binary
        # Inform the server of the new transfer type ('I' for Image/Binary, 'A' for ASCII).
        self._send_command(f"TYPE {'I' if self.binary_mode else 'A'}")
        self._get_response()
        print(f"Transfer mode set to: {'BINARY' if self.binary_mode else 'ASCII'} on server.")
    
    def nlst(self, path=''):
        """Retrieves a list of filenames from the server using NLST."""
        # --- Standard data transfer sequence ---
        # 1. Enter passive mode to get a data port.
        if self.passive_mode:
            self.enter_passive_mode()
        
        # 2. Send the actual command.
        self._send_command(f'NLST {path}')
        self._get_response() # Initial response (e.g., "150 Here comes the directory listing.")
        
        # 3. Read all data from the now-open data socket.
        data = b''
        while True:
            chunk = self.data_sock.recv(self.buffer_size)
            if not chunk:
                break
            data += chunk
        
        # 4. Close the data socket.
        self.data_sock.close()
        
        # 5. Read the final confirmation from the control socket.
        self._get_response() # Final response (e.g., "226 Directory send OK.")
        
        # Decode and return the data as a clean list of strings.
        return [line for line in data.decode('utf-8').splitlines() if line.strip()]

    def cwd(self, dirpath):
        """Changes the working directory on the server."""
        self._send_command(f'CWD {dirpath}')
        return self._get_response()

    def pwd(self):
        """Gets the current working directory from the server."""
        self._send_command('PWD')
        resp = self._get_response()
        # Parse the path from the response string, which is typically in quotes.
        # e.g., 257 "/path/to/dir" is the current directory.
        match = re.search(r'"(.*?)"', resp)
        if match:
            return match.group(1)
        return "Unknown" # Fallback if parsing fails.

    def retr(self, remote_file, local_path, binary=True):
        """Downloads a file from the server (RETR command)."""
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()
        
        # Set the transfer type for this specific operation.
        self._send_command(f"TYPE {'I' if binary else 'A'}")
        self._get_response()

        self._send_command(f'RETR {remote_file}')
        self._get_response()

        # Open the local file for writing ('wb' for binary, 'w' for text).
        with open(local_path, 'wb' if binary else 'w', encoding=None if binary else 'utf-8') as f:
            while True:
                chunk = self.data_sock.recv(self.buffer_size)
                if not chunk:
                    break
                f.write(chunk)
                if callback: callback(chunk) # update progress bar
        self.data_sock.close()
        return self._get_response()

    def stor(self, local_path, remote_path=None, binary=True):
        """Uploads a file to the server (STOR command)."""
        filename = os.path.basename(local_path) if remote_path is None else remote_path
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()

        self._send_command(f"TYPE {'I' if binary else 'A'}")
        self._get_response()

        self._send_command(f'STOR {filename}')
        self._get_response()
        
        # Read the local file and send its entire content over the data socket.
        with open(local_path, 'rb' if binary else 'r', encoding=None if binary else 'utf-8') as f:
            self.data_sock.sendall(f.read())
            
        self.data_sock.close()
        return self._get_response()
    
    # --- Simple Command Wrappers ---
    
    def mkd(self, dirname):
        """Creates a directory on the server."""
        self._send_command(f'MKD {dirname}')
        return self._get_response()

    def rmd(self, dirname):
        """Removes a directory from the server."""
        self._send_command(f'RMD {dirname}')
        return self._get_response()

    def delete(self, filename):
        """Deletes a file from the server."""
        self._send_command(f'DELE {filename}')
        return self._get_response()

    def rename(self, old_name, new_name):
        """Renames a file on the server (requires two commands)."""
        self._send_command(f'RNFR {old_name}') # RNFR = Rename From
        self._get_response()
        self._send_command(f'RNTO {new_name}') # RNTO = Rename To
        return self._get_response()

    def voidcmd(self, cmd):
        """Sends a command that doesn't involve a data transfer, like NOOP."""
        self._send_command(cmd)
        return self._get_response()
    
    def noop(self):
        """Sends a NOOP command, often used to keep a connection alive."""
        self._send_command('NOOP')
        return self._get_response()

    def quit(self):
        """Sends the QUIT command and properly closes the control connection."""
        try:
            self._send_command('QUIT')
            self._get_response()
        finally:
            # Ensure the socket is closed even if the server doesn't respond to QUIT.
            if self.control_sock:
                self.control_sock.close()
                self.control_sock = None