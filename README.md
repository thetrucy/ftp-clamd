Of course\! I can definitely help improve your `README.md` file. A good README is crucial for any project. I've analyzed your Python scripts to create a more comprehensive and user-friendly guide.

Here is a revised version of your README file. I've added more detail to each section as you requested, including prerequisites, a better-structured command reference with examples, and more thorough setup instructions.

-----

# ftp-clamd

A Python-based FTP client with integrated ClamAV anti-virus scanning. This tool ensures that all files are scanned for viruses by a ClamAV agent before they are uploaded to the FTP server, providing an extra layer of security for your file transfers.

It consists of two main components:

  * `ftp_client.py`: An interactive command-line FTP client.
  * `clamav_agent.py`: A server agent that receives files from the FTP client, scans them using ClamAV, and reports the result.

-----

## 📜 Table of Contents

  * [Prerequisites](https://www.google.com/search?q=%23-prerequisites)
  * [Setup and Configuration](https://www.google.com/search?q=%23-setup-and-configuration)
      * [1. FTP Server Setup](https://www.google.com/search?q=%231-ftp-server-setup)
      * [2. ClamAV Installation and Configuration](https://www.google.com/search?q=%232-clamav-installation-and-configuration)
  * [How to Run](https://www.google.com/search?q=%23-how-to-run)
  * [Usage and Commands](https://www.google.com/search?q=%23-usage-and-commands)

-----

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed:

1.  **Python 3:** Make sure Python 3 is installed on your system.
2.  **An FTP Server:** You need a running FTP server that the client can connect to.
3.  **ClamAV:** The ClamAV anti-virus engine must be installed on the same machine where you intend to run the `clamav_agent.py`.

-----

## 🛠️ Setup and Configuration

### 1\. FTP Server Setup

You need a functional FTP server. Below are basic setup guides for common FTP server software on Linux and Windows.

#### **Linux (vsftpd)**

`vsftpd` (Very Secure FTP Daemon) is a popular choice for Linux systems.

1.  **Install vsftpd:**
    ```bash
    sudo apt-get update
    sudo apt-get install vsftpd
    ```
2.  **Configure vsftpd:**
      * Open the configuration file: `sudo nano /etc/vsftpd.conf`.
      * It's recommended to disable anonymous access and allow local users to log in. Ensure the following lines are set:
        ```
        anonymous_enable=NO
        local_enable=YES
        write_enable=YES
        chroot_local_user=YES
        ```
      * To allow users to upload, you might need to add `allow_writeable_chroot=YES` at the end of the file.
3.  **Create an FTP User (Optional):** You can use an existing user or create a new one for FTP access.
4.  **Restart the Service:**
    ```bash
    sudo systemctl restart vsftpd
    ```

#### **Windows (FileZilla Server)**

FileZilla provides a straightforward GUI-based FTP server for Windows.

1.  **Download and Install:** Get the FileZilla Server installer from the [official website](https://filezilla-project.org/download.php?type=server).
2.  **Configure Users:**
      * Open the FileZilla Server interface.
      * Go to **Edit \> Users**.
      * In the "Users" panel, click **Add** to create a new user and set a password.
      * In the "Shared folders" panel, add the directories that this user can access and set their permissions (e.g., Read, Write, Delete).

### 2\. ClamAV Installation and Configuration

The `clamav_agent.py` script requires `clamscan` (on Linux) or `clamscan.exe` (on Windows) to be accessible.

#### **Linux (clamav)**

1.  **Install ClamAV:**
    ```bash
    sudo apt-get install clamav clamav-daemon
    ```
2.  **Update Virus Definitions:** Run `freshclam` to download the latest virus signatures. This may require you to stop the daemon first.
    ```bash
    sudo systemctl stop clamav-freshclam
    sudo freshclam
    sudo systemctl start clamav-freshclam
    ```
3.  **Check Path:** The script expects `clamdscan` to be at `/usr/bin/clamdscan`. You can verify this with `which clamdscan`. If it's different, you must update the path in the `get_clamscan_path()` function in `clamav_agent.py`.

#### **Windows**

1.  **Install ClamAV:** Download the official installer from the [ClamAV website](https://www.clamav.net/downloads).
2.  **Check Path:** The script expects `clamscan.exe` to be at `C:\\Program Files\\ClamAV\\clamscan.exe`. If you installed it in a different location, you must update the path in the `get_clamscan_path()` function in `clamav_agent.py`.
3.  **Update Virus Definitions:** Run the "Virus Definition Update" tool that comes with the installation.

-----

## ▶️ How to Run

1.  **Clone the Repository:**

    ```bash
    git clone <your-repository-link>
    cd ftp-clamd
    ```

2.  **Start the ClamAV Agent:**
    Open a terminal or command prompt and run the agent. This agent will listen for files to scan.

    ```bash
    python clamav_agent.py
    ```

    You should see the output: `[SERVER] ClamAV scanning agent listening for clients on port 12067...`.

3.  **Start the FTP Client:**
    Open a **second** terminal or command prompt and run the client.

    ```bash
    python ftp_client.py
    ```

    You will be greeted with the client's welcome message and a command prompt.

-----

## 🖥️ Usage and Commands

The client works like a standard command-line FTP program.

### Connecting to the Server

First, connect to your FTP server using the `open` command.

```
ftp> open <host> <port> <username> <password>
```

**Example:**

```
ftp> open 127.0.0.1 21 myuser mypassword
✅ 220 (vsFTPd 3.0.3)
✅ Successfully connected to 127.0.0.1.
📍 Current directory: /home/myuser
ftp:/home/myuser>
```

### Command Reference

Here is a list of available commands, which can also be viewed by typing `help` in the client.

| Command | Description | Example |
|---|---|---|
| **`ls`** | Lists files and folders in the current remote directory. | `ftp:/home/myuser> ls` |
| **`cd <dir>`** | Changes the directory on the FTP server. | `ftp:/home/myuser> cd public_html` |
| **`pwd`** | Shows the current directory on the server. | `ftp:/home/myuser> pwd` |
| **`lcd <dir>`** | Changes the current directory on your local machine. | `ftp> lcd C:\Users\Me\Documents` |
| **`mkdir <dir>`**| Creates a new directory on the server. | `ftp:/home/myuser> mkdir new_folder` |
| **`rmdir <dir>`**| Deletes a directory on the server. | `ftp:/home/myuser> rmdir old_folder` |
| **`delete <file>`**| Deletes a file on the server. | `ftp:/home/myuser> delete old_file.txt` |
| **`rename <old> <new>`**| Renames a file or directory on the server. | `ftp:/home/myuser> rename file.txt new_name.txt` |
| **`put <local_file>`** | **Scans** a local file with the ClamAV agent and then uploads it. The upload is cancelled if a virus is found. | `ftp:/home/myuser> put "C:\\files\\upload.zip"` |
| **`get <remote_file>`**| Downloads a single file from the server. | `ftp:/home/myuser> get important_document.docx` |
| **`mput`** | Uploads multiple files from a local directory, with an option for recursive upload. Each file is scanned. | `ftp:/home/myuser> mput` |
| **`mget <remote_dir>`**| Downloads an entire directory recursively from the server. | `ftp:/home/myuser> mget my_project` |
| **`passive <on/off>`**| Toggles FTP passive mode. | `ftp:/home/myuser> passive on` |
| **`binary` / `ascii`** | Sets the file transfer mode to binary (for files) or ASCII (for text). | `ftp:/home/myuser> binary` |
| **`status`** | Shows the current connection status, transfer mode, and ClamAV agent configuration. | `ftp:/home/myuser> status` |
| **`set_clamav_agent`**| Allows you to change the host and port for the ClamAV agent. | `ftp:/home/myuser> set_clamav_agent` |
| **`close`** | Disconnects from the FTP server. | `ftp:/home/myuser> close` |
| **`quit` / `bye`**| Disconnects and exits the FTP client. | `ftp:/home/myuser> quit` |
