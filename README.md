MoD & Police - Secure Legal Document Management System (DMS)

A secure, client-side encrypted Document Management System designed for law enforcement and defense records, featuring robust chain-of-custody tracking, time-based document expiration, and multi-tier user clearance management.
Key Features

    End-to-End Client-Side Encryption: Documents are encrypted and decrypted locally in the browser using AES-GCM 256-bit and PBKDF2 key derivation. The server only ever stores ciphertexts and cryptographic metadata.

    Cryptographic Integrity & Signatures: Files are bound with SHA-256 hashes and ECDSA digital signatures upon upload.

    Built-In Secure Document Viewer: Decrypts and previews documents (images, PDFs, text) directly in-memory using an interactive modal viewer without triggering raw file downloads.

    Immutable Chain-of-Custody Ledger: Every action, access attempt, and viewing reason is logged to an audit timeline.

    Role-Based Access Control & Approvals: Multi-level clearances (Investigator, External Witness, Supervisor, Admin) with admin approval queues for user registrations and password resets.

    Time-Based Access Expiration: Documents can be set with optional expiration windows after which access is automatically revoked.

Project Structure
Plaintext

├── backend.py        # Python Flask backend server and SQLite database handler
├── requirements.txt  # Python dependency configurations
└── index.html        # Single-file Tailwind CSS frontend interface & Web Crypto client

Local Installation & Setup
1. Backend Setup

Ensure you have Python installed, then set up the backend dependencies:
Bash

# Install required Python packages
pip install -r requirements.txt

# Run the local Flask development server
python backend.py

The backend server will run at [http://127.0.0.1:8000](http://127.0.0.1:8000).
2. Frontend Setup

Open the index.html file directly in any modern web browser or serve it using a local static server.

(Note: Ensure the API_URL variable inside index.html points to your active backend server address—default is [http://127.0.0.1:8000](http://127.0.0.1:8000) for local development).
Default Administrator Credentials

When the database initializes for the first time, a default administrator account is generated:

    Badge ID: ADMIN-01

    Passcode: admin123

    Role: Admin (Level 3)

Cloud Deployment Guide
Hosting the Backend (e.g., Render)

    Push your backend code (backend.py and requirements.txt) to a GitHub repository.

    Create a new Web Service on Render.

    Set the build command to pip install -r requirements.txt.

    Set the start command to gunicorn backend:app.

Hosting the Frontend (e.g., Cloudflare Pages / GitHub Pages)

    Update the API_URL variable in index.html to point to your live backend domain (e.g., [https://your-app-name.onrender.com](https://your-app-name.onrender.com)).

    Deploy index.html via Cloudflare Pages, GitHub Pages, or any static web host..