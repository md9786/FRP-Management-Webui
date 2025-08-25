<img width="1918" height="904" alt="image" src="https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/dash.png?raw=true" />
# FRP Management UI Wiki

Welcome to the official wiki for the FRP Management UI. This document provides a comprehensive guide to all the features and functionalities of the application.

## Table of Contents
1.  [Overview](#1-overview)
2.  [Login Page](#2-login-page)
3.  [Dashboard](#3-dashboard)
4.  [Setup & Presets](#4-setup--presets)
    - [4.1 Setup Client](#41-setup-client)
    - [4.2 Setup Server](#42-setup-server)
    - [4.3 Manage Presets](#43-manage-presets)
    - [4.4 System Management](#44-system-management)
5.  [Manage FRP](#5-manage-frp)
    - [5.1 Clients Tab](#51-clients-tab)
    - [5.2 Servers Tab](#52-servers-tab)
    - [5.3 Editing a Configuration](#53-editing-a-configuration)
6.  [Manage EFRP](#6-manage-efrp)
7.  [Show Status](#7-show-status)
8.  [Settings](#8-settings)
9.  [How to Add Images to this Wiki](#9-how-to-add-images-to-this-wiki)

---

## 1. Overview

The FRP Management UI is a web-based graphical interface designed to simplify the installation, configuration, and management of FRP (Fast Reverse Proxy) clients and servers. It provides real-time system monitoring, live log streaming, and an intuitive preset system to streamline repetitive setups.

---

## 2. Login Page

This is the entry point to the application. Access is protected by a username and password.

-   **Default Credentials**:
    -   Username: `admin`
    -   Password: `admin`
-   **Functionality**: Users must enter their credentials to gain access to the dashboard. After updating credentials on the Settings page, the user will be redirected here to log in again.


![Login Page](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/login.png?raw=true "The login screen for the FRP Management UI.")

---

## 3. Dashboard

The Dashboard is the landing page after a successful login. It provides a high-level, real-time overview of your system and FRP connections.


![Dashboard View](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/dash.png?raw=true "The main dashboard with all monitoring widgets.")

### Widgets

-   **System Information**: A top bar showing four key metrics about the host machine.
    -   **CPU Usage**: The current CPU load percentage. The color changes from green (<50%), to yellow (50-80%), to red (>80%) based on usage.
    -   **RAM Usage**: The amount of memory currently in use versus the total available memory. The color changes based on the percentage of RAM used (green <70%, yellow 70-90%, red >90%).
    -   **Network Upload**: The current outbound network traffic speed.
    -   **Network Download**: The current inbound network traffic speed.

-   **Connection Overview**: This card provides a quick status check for all configured FRP clients and servers.
    -   **Status Dots**: Each entry has a colored dot indicating its current status, determined by analyzing recent logs:
        -   **Green**: Running correctly.
        -   **Yellow**: Running, but with warnings in the logs.
        -   **Red**: An error has occurred.
        -   **Gray**: The service is stopped.

-   **Network History**: A line graph that visualizes the network upload and download speeds (in KB/s) over the last 5 minutes, updating every 5 seconds.

---

## 4. Setup & Presets

This section is the control center for creating new FRP configurations and managing templates (presets). It is organized into four tabs.


![Setup & Presets Page](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/setup.png?raw=true "The main setup page with its four primary tabs.")

### 4.1 Setup Client

This tab is for creating a new `frpc` (client) configuration and its associated system service.

-   **Load Preset**: Select a saved client preset to auto-fill the form fields.
-   **Client Name**: A unique, descriptive name for the client (e.g., `my-game-server`). This name is used for the configuration file and the service.
-   **Server IP / Port**: The address and port of the `frps` server this client will connect to.
-   **Auth Token**: The authentication token that must match the server's token.
-   **Transport**: The protocol to use for the connection (TCP, Websocket, QUIC, KCP).
-   **Enable TCP Mux**: Choose whether to enable TCP stream multiplexing over a single connection.
-   **Local Ports**: The local ports on the client machine to be exposed. You can specify single ports, commas, and ranges (e.g., `22, 80, 443, 6000-6010`).
-   **Setup Client Button**: Submits the form, creates the `.toml` configuration file, and enables/starts the `frpc@<client-name>.service`.


### 4.2 Setup Server

This tab is for creating a new `frps` (server) configuration and its associated system service.

-   **Load Preset**: Select a saved server preset to auto-fill the form.
-   **Server Name**: A unique, descriptive name for the server (e.g., `public-vps-1`).
-   **Bind Port**: The main port the FRP server will listen on for client connections.
-   **Protocol**: Additional protocols to enable (QUIC, KCP).
-   **Enable TCP Mux**: Choose whether to enable TCP stream multiplexing.
-   **Auth Token**: The token clients must use to connect.
-   **Setup Server Button**: Submits the form, creates the configuration file, and starts the `frps@<server-name>.service`.


### 4.3 Manage Presets

This tab allows you to create and delete reusable templates for both client and server setups to speed up configuration.

-   **Client Presets / Server Presets Tabs**: Switch between managing presets for clients or servers.
-   **Create New Preset Form**: Fill out the details for a new preset and click "Save". The preset will appear in the "Existing Presets" list and the "Load Preset" dropdown on the setup forms.
-   **Existing Presets List**: Shows all saved presets. Each item has a **Delete** button.




### 4.4 System Management

This tab provides high-level actions for the FRP installation itself.

-   **Install/Update FRP**: Downloads the latest version of FRP from GitHub, installs the binaries (`frps`, `frpc`), and sets up the necessary systemd service template files. Use this for a first-time install or to upgrade.
-   **Uninstall FRP**: **(Warning: Irreversible)** This action stops all services, removes all configuration files, deletes the binaries, and removes the systemd files. It completely scrubs FRP from the system. A confirmation prompt will appear before proceeding.



---

## 5. Manage FRP

This page is for the day-to-day management of your running FRP services.


![Manage FRP Page](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/manage.png?raw=true "The primary management interface for clients and servers.")

### 5.1 Clients Tab

-   **Global Controls**: **Start All**, **Stop All**, and **Restart All** buttons perform the respective action on every configured client simultaneously.
-   **Client Tabs**: Each configured client has its own tab for individual management.
-   **Individual Controls**: Within each tab, you can **Start**, **Stop**, **Restart**, or **Edit Config** for that specific client.
-   **Live Logs**: A real-time log viewer for the selected client service.
    -   **Search Bar**: Instantly filter logs for specific keywords.
    -   **Level Filters**: Filter logs by severity: **INFO**, **WARN**, or **ERROR**.



### 5.2 Servers Tab

This tab mirrors the functionality of the Clients tab but is dedicated to `frps` server instances. It includes the same global controls, individual controls, and live log viewer.

### 5.3 Editing a Configuration

Clicking the **Edit Config** button on any client or server tab takes you to this page.

-   **Config Name**: You can rename the configuration here. This will automatically stop the old service, rename the config file, and start a new service with the new name.
-   **Config Content**: A text area containing the full `.toml` configuration file. You can make any manual edits here.
-   **Save**: Saves the changes to the file and restarts the service to apply them.



---

## 6. Manage EFRP

This page provides a simplified management interface for the EFRP service.

-   **Controls**: **Start** and **Stop** buttons to manage the EFRP service.
-   **Live Logs**: A real-time log viewer for the EFRP service, complete with search and level filtering.


![Manage EFRP Page](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/EFRP.png?raw=true "The management interface for the EFRP service.")

---

## 7. Show Status

This page gives a raw, text-based summary of the entire FRP setup, which can be useful for quick debugging or copying information.

-   **Version**: The currently installed FRP version.
-   **Running Services**: A list of all `frpc` and `frps` services that are currently active.
-   **Enabled Services**: A list of all `frpc` and `frps` services that are enabled to start on boot.
-   **Server/Client Configs**: A directory listing of all `.toml` files in the server and client configuration folders.


![Show Status Page](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/status.png?raw=true "The text-based status overview page.")

---

## 8. Settings

This page allows you to manage the credentials for accessing the web UI.

-   **Username**: Change the login username.
-   **Current Password**: Must be provided to make any changes.
-   **New Password / Confirm New Password**: Enter a new password here. Leave blank to keep the current one.
-   **Save Changes**: After saving, you will be logged out and redirected to the login page to sign in with your new credentials.

**Screenshot Placeholder:**
![Settings Page](https://github.com/md9786/FRP-Management-Webui/blob/main/screenshots/settings.png?raw=true "The user settings and password change form.")

## 9. Building and Running the Application

This section provides instructions on how to compile the Go backend and run the entire application from the source code.

### Prerequisites

-   **Go**: You must have the Go programming language (version 1.18 or newer) installed on your system. You can download it from the [official Go website](https://go.dev/dl/).

### 1. File Structure

Before building, ensure your project files are organized correctly. The application expects a specific directory structure for the HTML templates.

```
/your-project-root
├── main.go         <-- Rename main.txt to main.go
└── /templates/
    ├── edit.html
    ├── efrp.html
    ├── home.html
    ├── login.html
    ├── logs.html
    ├── manage-frp.html
    ├── settings.html
    ├── setup-frp.html
    ├── sidebar.html
    └── status.html
```

-   Rename `main.txt` to `main.go`.
-   Create a directory named `templates`.
-   Move all `.html` files into the `templates` directory.

### 2. Initializing the Go Module

Navigate to your project's root directory in your terminal and initialize a Go module. This will create a `go.mod` file to manage dependencies.

```bash
# Replace 'my-frp-manager' with your desired module name
go mod init my-frp-manager
```

### 3. Fetching Dependencies

Once the module is initialized, run `go mod tidy`. This command will find all the required external packages (like Gin, gopsutil, etc.) and download them.

```bash
go mod tidy
```

### 4. Building the Application

Now, compile the Go source code into a single executable binary.

-   **For Linux/macOS**:
    ```bash
    go build -o frp-manager
    ```
-   **For Windows**:
    ```bash
    go build -o frp-manager.exe
    ```
This command creates an executable file named `frp-manager` (or `frp-manager.exe`) in your project root.

### 5. Running the Application

To run the application, execute the binary you just created. Since the application performs system-level operations (managing services, writing to `/root/`), it typically requires superuser/administrator privileges.

-   **On Linux/macOS**:
    ```bash
    sudo ./frp-manager
    ```
-   **On Windows**:
    Open a Command Prompt or PowerShell **as an Administrator** and run:
    ```bash
    .\frp-manager.exe
    ```

After running the command, you should see the message "Server starting on :5001..." in your terminal. You can now access the web UI by navigating to `http://localhost:5001` in your web browser.
