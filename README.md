# Secure FTP via Clamscan

A Python-based FTP client with integrated ClamAV anti-virus scanning. This tool ensures that all files are scanned for viruses by a ClamAV agent before they are uploaded to the FTP server.

It consists of two main components:

  * `my_ftp.py`: A custom FTP library, built from the ground up using Python's socket module, that handles the core protocol commands and data transfers.
  * `ftp_client.py`: An interactive command-line FTP client.
  * `clamav_agent.py`: A server agent that receives files from the FTP client, scans them using ClamAV, and reports the result.

-----

## Table of Contents

  * [Prerequisites](#prerequisites)
  * [Setup and Configuration](#setup-and-configuration)
      * [1. FTP Server Setup](#1-ftp-server-setup)
      * [2. ClamAV Installation and Configuration](#2-clamav-installation-and-configuration)
  * [How to Run](#how-to-run)
  * [Usage and Commands](#usage-and-commands)

-----

## Prerequisites

Before you begin, ensure you have the following installed:

1.  **Python 3:** Make sure Python 3 is installed on your system.
2.  **An FTP Server:** You need a running FTP server that the client can connect to.
3.  **ClamAV:** The ClamAV anti-virus engine must be installed on the same machine where you intend to run the `clamav_agent.py`.

-----

## Setup and Configuration

### 1\. FTP Server Setup

You need a functional FTP server. Below are basic setup guides for common FTP server software on Linux and Windows.

#### **Linux (vsftpd)**

`vsftpd` (Very Secure FTP Daemon) is a popular choice for Linux systems.

Set up tutorial [VSFTPD setup](https://youtu.be/ISVyGxYfAGg?si=ggvcTokEHsi4RnYv)

Below is a brief summary:

1.  **Install vsftpd:**
    ```bash
    sudo apt update
    sudo apt install vsftpd
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
3.  **Create an FTP User (Optional):** You can use an existing user or create a new one for FTP access.
4.  **Restart the Service:**
    ```bash
    sudo systemctl restart vsftpd
    ```
5. **Check if the Service works**
   ```bash
    sudo systemctl status vsftpd
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

The `clamav_agent.py` script requires `clamdscan` (on Linux) or `clamscan.exe` (on Windows) to be accessible.

#### **Linux (clamav)**

1.  **Install ClamAV:**
    ```bash
    sudo apt install clamav clamav-daemon
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

## How to Run

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/thetrucy/ftp-clamd
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

    You will be greeted with the client's welcome message and a command prompt:

    ```bash
    🚀 FTP Client with ClamAV Integration 🚀
    🧠 Type 'help' or '?' for available commands.
    💡 Use 'open <host> <port> <username> <password>' to connect.
    ftp>
    ```

-----

## Usage and Commands

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

| No. | Command | Expected Output |
|---|---|---|
| 1 | **`ls`** | Displays a list of files and folders in the server’s current directory. |
| 2 | **`cd <dir>`** | Changes the current folder on the server and shows a success notification. |
| 3 | **`pwd`** | Shows the current directory path on the server. |
| 4 | **`lcd <dir>`** | Displays the current local directory and allows changing it. |
| 5 | **`mkdir <dir>`**, **`rmdir <dir>`** | Creates or removes a folder on the server and shows a success notification. |
| 6 | **`delete <file>`** | Deletes a file in the server’s current directory and shows a success notification. |
| 7 | **`rename <old> <new>`** | Renames a file or folder on the server and shows a success notification. |
| 8 | **`get <remote_file>`**, **`recv <remote_file>`** | Downloads a file from the server to the local machine, with a progress bar and notifications. |
| 9 | **`put <local_file>`** | Uploads a file from the local machine to the server after ClamAV scanning, with a progress bar and notifications. |
| 10 | **`mput`** | Uploads multiple files, scanning each one and asking for confirmation if prompts are enabled. |
| 11 | **`mget <remote_dir>`** | Downloads multiple files from the server, scanning each before download, and asks for confirmation if prompts are enabled. |
| 12 | **`prompt`** | Toggles confirmation prompts for each file during `put` or `get` operations. |
| 13 | **`ascii`**, **`binary`** | Switches the file transfer mode between ASCII (text) and binary (files). |
| 14 | **`status`** | Displays current connection status, transfer mode, and ClamAV agent configuration. |
| 15 | **`passive <on/off>`** | Toggles passive mode for FTP connections and shows a status message. |
| 16 | **`open`** | Connects to the FTP server and shows success or failure notification. |
| 17 | **`close`** | Disconnects from the server and sends a goodbye message. |
| 18 | **`quit`**, **`bye`** | Exits the client, disconnects from the server, and sends a goodbye message. |
| 19 | **`help`**, **`?`** | Displays the list of available commands. |
| 20 | **`set_clamav_agent`** | Allows configuring the ClamAV agent’s host and port. |
