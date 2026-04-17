# Project Vanish Lite 🚀

**Project Vanish Lite** is a secure, disposable Linux user workspace system designed for privacy, compliance, and stateless computing. It dynamically provisions temporary system users, enforces mode-based policies, and guarantees a full teardown with zero local persistence.

## 🌟 Key Features

-   **Dynamic User Lifecycle**: Instant creation and automated cleanup of disposable Linux users.
-   **Mode-Based Policies**: Predefined security modes:
    -   `privacy`: RAM-backed home directory, telemetry blocking.
    -   `exam`: Strict network restrictions, persistent mounts for logs.
    -   `online`: Domain-based firewall filtering (Whitelist/Blacklist).
    -   `secure`: Hardened environment for sensitive tasks.
-   **Admin Dashboard**: A sleek, web-based control panel for managing sessions, policies, and presets.
-   **Guaranteed Teardown**: Robust cleanup mechanism ensuring no leftover processes or data.
-   **Cloud Integration**: Encrypted persona data sync with MongoDB and Supabase.

## 🏗️ Architecture

-   **Engine (C++)**: Core OS-level logic for user management, mount handle, and policy enforcement via `iptables` and `systemd`.
-   **Admin Panel (Python/Flask)**: Centralized management UI with live status tracking and log tailing.
-   **Client Tools**: Python-based CLI for selective state synchronization and encryption.

## 🚀 Getting Started

### Prerequisites

-   Linux (Ubuntu/Debian recommended)
-   `g++`, `make`, `libsqlite3-dev`
-   Python 3.8+
-   `sudo` privileges (required for user management and networking)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/vighnesh2005/PDP_Project.git
    cd PDP_Project
    ```

2.  **Build the engine:**
    ```bash
    make all
    ```

3.  **Setup the Admin Panel:**
    ```bash
    cp .env.example .env
    # Edit .env with your credentials
    pip install -r admin_panel/requirements.txt
    ```

### Running the System

-   **Start the Admin Panel:**
    ```bash
    sudo make admin-panel
    ```
    Access at `http://localhost:8080`.

-   **CLI Usage:**
    ```bash
    sudo ./vanish start privacy --username temp_user
    ```

## 🧪 Testing

Run the comprehensive test suite:
```bash
# Unit tests
scripts/test_everything.sh

# Integration tests (requires sudo)
sudo scripts/test_modes_integration.sh
```

## 📂 Project Structure

- `engine/`: C++ core engine source code.
- `admin_panel/`: Python/Flask server and frontend assets.
- `report1/`: Technical project report (LaTeX).
- `scripts/`: Integration and unit test scripts.
- `docs/`: Supplementary documentation (Roadmap, Features).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Created for the PDP Project course.*
