# Go-Based FRP Management UI

A comprehensive, self-hosted web UI for managing [FRP (A fast reverse proxy)](https://github.com/fatedier/frp) clients and servers on a Linux system. Built with Go and a modern frontend stack, this dashboard provides real-time monitoring, configuration management, live log streaming, and more, all from a single, easy-to-use interface.

 
*(Note: Screenshot is a placeholder representation)*

## ✨ Features

- **Real-time Dashboard:** Monitor system vitals like CPU usage, RAM consumption, and live network throughput.
- **Connection Overview:** See the status (Running, Stopped, Warning, Error) of all your FRP clients and servers at a glance.
- **Live Network Graph:** Visualize network upload and download history over the last 5 minutes.
- **Simplified Setup:** Configure and launch new `frps` servers and `frpc` clients directly from the web UI.
- **Full Service Management:** Start, stop, and restart individual or all FRP services with a single click.
- **Live Log Streaming:** View logs for any client or server in real-time, complete with search and filtering by log level (INFO, WARN, ERROR).
- **In-Browser Configuration Editor:** Edit TOML configuration files directly in the browser and apply changes by restarting the service.
- **Preset System:** Save and load common client and server configurations as presets to speed up new deployments.
- **System Administration:** Includes one-click options to install the latest version of FRP or to completely uninstall it.
- **Secure Access:** Features a user login system with options to change username and password.
- **Modern, Responsive UI:** Built with Tailwind CSS for a clean and responsive experience on both desktop and mobile.

## 🛠️ Technology Stack

- **Backend:** Go, Gin Web Framework
- **Frontend:** HTML5, Tailwind CSS, Vanilla JavaScript
- **Real-time Communication:** WebSockets
- **Data Visualization:** Chart.js
- **System Metrics:** [gopsutil](https://github.com/shirou/gopsutil)
- **Service Management:** Direct calls to `systemctl` for robust service handling.

## 🚀 Getting Started

### Prerequisites
- A Linux server with `systemd`.
- Go (version 1.18+ recommended).
- Root or `sudo` privileges (required for service management and file storage in `/root`).

### Installation
1.  Build the binary from the `main.go` source file:
    ```bash
    go build -o frp-panel .
    ```
2.  Create a directory for the application's templates.
    ```bash
    mkdir templates
    ```
3.  Place all `.html` files into the `templates` directory.
4.  Run the binary. The server will start on port `5001`.
    ```bash
    ./frp-panel
    ```
5.  Access the UI in your browser at `http://<your-server-ip>:5001`.
6.  Log in with the default credentials:
    - **Username:** `admin`
    - **Password:** `admin`

### First-Time Setup
After logging in for the first time:
1.  Navigate to **Setup & Presets** from the sidebar.
2.  Select the **System Management** tab.
3.  Click the **Install/Update FRP** button. This will download the latest `frps` and `frpc` binaries from GitHub and set up the necessary `systemd` service files on your system.

## 📁 Configuration & Data Storage

The application stores all its data and FRP configurations in the `/root/frp/` directory by default. Ensure this path is accessible and writable by the user running the application.

- `/root/frp/client/`: Stores `frpc` client configurations (`.toml` files).
- `/root/frp/server/`: Stores `frps` server configurations (`.toml` files).
- `/root/frp/users.json`: Stores user credentials (passwords are hashed).
- `/root/frp/presets.json`: Stores client configuration presets.
- `/root/frp/server_presets.json`: Stores server configuration presets.

## 📡 API Overview

The backend provides a RESTful API for the frontend to consume.

- `GET /api/system/info`: Provides real-time system metrics (CPU, RAM, Network).
- `GET /api/system/history`: Returns historical network data for the dashboard chart.
- `GET /api/connections/status`: Fetches the current status of all configured FRP services.
- `GET /api/presets`, `POST /api/presets/save`, etc.: Full CRUD operations for managing client and server presets.
- `GET /ws/logs/:type/:name`: The WebSocket endpoint for live log streaming.

## 📄 License

This project is licensed under the MIT License.
