# Project Vanish Lite

## Updated 4-Week Execution Plan (Course MVP)

------------------------------------------------------------------------

## 🎯 Final Project Vision

Project Vanish Lite is a disposable Linux user workspace system that:

-   Dynamically provisions temporary system users
-   Injects encrypted cloud-based persona data
-   Allows selective push/pull of configurations
-   Guarantees full teardown and zero local persistence
-   Demonstrates secure lifecycle management

------------------------------------------------------------------------

# 📅 Week 1 --- Disposable User Lifecycle Engine

## Goal:

Build a rock-solid temporary user system with guaranteed cleanup.

### Deliverables:

-   CLI: `vanish start`, `vanish stop`
-   Random temp user generation (`vanish_<random>`)
-   User creation (`useradd -m`)
-   Safe session switching
-   Process kill on exit (`pkill -u`)
-   User deletion (`userdel -r`)
-   Orphan user detection on startup
-   Signal handling (SIGINT, SIGTERM)
-   Logging to `/var/log/vanish.log`

### Acceptance Criteria:

-   No leftover users after exit
-   No leftover processes
-   Safe repeated execution
-   Proper error handling

------------------------------------------------------------------------

# 📅 Week 2 --- Local Persona Injection

## Goal:

Allow injection of local configuration bundles.

### Deliverables:

-   Support `profile.tar.gz`
-   Extract profile into temp user's home
-   Fix file permissions
-   Add simple metadata file
-   Implement manual selection of files to inject

### Acceptance Criteria:

-   Temp session loads injected configs
-   No impact on main user
-   Clean teardown still works

------------------------------------------------------------------------

# 📅 Week 3 --- Encryption + Cloud Sync

## Goal:

Add encrypted cloud state storage.

### Deliverables:

-   Python crypto module (AES via `cryptography` library)
-   Password-based key derivation (PBKDF2)
-   Encrypt tar files before upload
-   FastAPI backend for blob storage
-   Download + decrypt before injection
-   Simple token-based identification

### Acceptance Criteria:

-   Server stores only encrypted data
-   Decryption restores correct state
-   Incorrect password fails safely

------------------------------------------------------------------------

# 📅 Week 4 --- Selective Sync & Polishing

## Goal:

Allow selective push/pull of cloud items.

### Deliverables:

-   `metadata.json` index per user
-   CLI selector for import/export
-   Manual selection of directories/files
-   Full session lifecycle integration
-   Documentation (Threat Model, Architecture)
-   Demo script

### Acceptance Criteria:

-   User can choose what to import
-   User can choose what to upload
-   No leftover data after session
-   Clean demo flow

------------------------------------------------------------------------

# 🧱 Final Folder Structure

vanish-lite/ │ ├── engine/ │ ├── user_manager.sh │ ├── cleanup.sh │ └──
utils.sh │ ├── client/ │ ├── manager.py │ ├── sync.py │ ├── crypto.py │
└── selector.py │ ├── server/ │ ├── app.py │ └── storage/ │ ├── tests/ │
├── lifecycle_test.sh │ └── sync_test.sh │ ├── docs/ │ ├──
architecture.md │ ├── threat_model.md │ └── demo_steps.md │ ├──
requirements.txt ├── README.md └── INSTALL.md

------------------------------------------------------------------------

# 📊 Estimated Code Size

  Component           LOC
  ------------------- --------------------
  User lifecycle      300--400
  Persona injection   250--350
  Encryption module   200
  Server backend      200
  Selective sync      300
  Logging & safety    200
  **Total**           **1400--1700 LOC**

------------------------------------------------------------------------

# 🏆 What Makes This Project Strong

-   OS-level user lifecycle management
-   Secure teardown guarantee
-   Encrypted cloud persistence
-   Selective state synchronization
-   Stateless computing concept
-   Clear threat model & architecture

------------------------------------------------------------------------

# 🚀 End Goal Statement

Project Vanish Lite demonstrates a secure, disposable computing model
that decouples user state from hardware using dynamic user provisioning
and encrypted cloud persona injection.

------------------------------------------------------------------------

vanish-lite/
│
├── engine/
│   ├── user_manager.sh
│   └── cleanup.sh
│
├── client/
│   ├── manager.py
│   ├── sync.py
│   ├── crypto.py
│   └── selector.py
│
├── server/
│   ├── app.py
│   └── storage/
│
├── data/
│   └── metadata_schema.json
│
├── tests/
│
└── docs/