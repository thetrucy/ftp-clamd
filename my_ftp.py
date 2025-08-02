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
        self.passive_mode = True
        self.binary_mode = True
        self.buffer_size = buffer_size
        self.timeout = timeout
        self.welcome_message = ""

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
        """Create a listening socket and send PORT command for Active Mode."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener_sock:
            # Bind to an ephemeral port on the same interface as the control connection
            host_ip = self.control_sock.getsockname()[0]
            listener_sock.bind((host_ip, 0))
            listener_sock.listen(1)
            
            ip, port = listener_sock.getsockname()
            
            # Format IP and port for the PORT command
            p1 = port // 256
            p2 = port % 256
            host_parts = ip.replace('.', ',')
            
            port_command = f"PORT {host_parts},{p1},{p2}"
            self._send_command(port_command)
            self._get_response() # Server confirms PORT command
            
            # Accept the incoming data connection from the server
            self.data_sock, _ = listener_sock.accept()

    def enter_passive_mode(self):
        """Switch to passive mode and open data socket."""
        self._send_command('PASV')
        resp = self._get_response()
        # Extract host and port from reply
        match = re.search(r'\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)', resp)
        if not match:
            raise FTPError(f"Failed to parse PASV response: {resp}")
        
        host_parts = match.group(1).split(',')
        p1, p2 = int(match.group(2)), int(match.group(3))

        data_host = '.'.join(host_parts)
        data_port = (p1 * 256) + p2
        self.data_sock = socket.create_connection((data_host, data_port), timeout=self.timeout)
        # return resp

    def set_pasv(self, value):
        """Enable or disable passive mode."""
        if not isinstance(value, bool):
            raise TypeError("Passive mode value must be a boolean (True or False)")
        self.passive_mode = value

    def set_binary_mode(self, binary: bool): # To set global transfer mode
        """Sets the global transfer mode (binary or ASCII) for subsequent operations."""
        if not self.control_sock:
            raise FTPConnectError("Not connected to any FTP server.")
        self.binary_mode = binary
        # It's good practice to immediately tell the server the type
        self._send_command(f"TYPE {'I' if self.binary_mode else 'A'}")
        self._get_response()
        print(f"Transfer mode set to: {'BINARY' if self.binary_mode else 'ASCII'} on server.")
   
    def nlst(self, path=''):
        """List names using NLST."""
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()

        self._send_command(f'NLST {path}')
        resp = self._get_response() # Initial response (e.g., "150 Here comes the directory listing.")
        data = b''
        while True:
            chunk = self.data_sock.recv(self.buffer_size)
            if not chunk:
                break
            data += chunk
        self.data_sock.close()
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

    def retr(self, remote_file, local_path, binary=True):
        """Download remote_file to local_path."""
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()
        
        self._send_command(f"TYPE {'I' if binary else 'A'}")
        self._get_response()

        self._send_command(f'RETR {remote_file}')
        self._get_response()

        with open(local_path, 'wb' if binary else 'w', encoding=None if binary else 'utf-8') as f:
            while True:
                chunk = self.data_sock.recv(self.buffer_size)
                if not chunk:
                    break
                f.write(chunk)
        self.data_sock.close()
        return self._get_response()

    def stor(self, local_path, remote_path=None, binary=True):
        """Upload local_file to server as remote_path (or basename if not specified)."""
        filename = os.path.basename(local_path) if remote_path is None else remote_path
        if self.passive_mode:
            self.enter_passive_mode()
        else:
            self.enter_active_mode()

        self._send_command(f"TYPE {'I' if binary else 'A'}")
        self._get_response()

        self._send_command(f'STOR {filename}')
        self._get_response()
        
        with open(local_path, 'rb' if binary else 'r', encoding=None if binary else 'utf-8') as f:
            self.data_sock.sendall(f.read())
        self.data_sock.close()
        return self._get_response()
    
    def mkd(self, dirname):
        self._send_command(f'MKD {dirname}')
        return self._get_response()

    def rmd(self, dirname):
        self._send_command(f'RMD {dirname}')
        return self._get_response()

    def delete(self, filename):
        self._send_command(f'DELE {filename}')
        return self._get_response()

    def rename(self, old_name, new_name):
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
