Secure Chat Application with RSA Encryption
Overview

This project implements a simple secure chat system in Python using RSA public-key encryption to protect messages and file transfers between clients and a server. It supports user authentication, private messaging, file sharing, and basic commands.
Features

    Encrypted Communication: Uses RSA keys for secure message and file transfer encryption.

    User Authentication: Supports new user registration and login with username/password.

    Private Messaging: Send messages privately to other connected users.

    File Transfers: Send and receive files securely between clients and server.

    Basic Commands:

        .help — Display command info.

        .exit — Disconnect from the server.

        .file <filename> — Send a file to the server.

        .list_files — List files available on the server.

        .download <filename> — Download a file from the server.

Files and Structure

    client.py: Client application to connect to the server, authenticate, send/receive messages, and manage file transfers.

    server.py: Server application managing multiple clients, authenticating users, relaying messages, and handling file storage.

    users.txt: Stores registered usernames and passwords in plain text (for simplicity).

    server_files/: Directory on the server to store uploaded files.

    client_files/: Directory on the client side to store downloaded files.

Requirements

    Python 3.x

    rsa library (pip install rsa)

How to Run
Server

    Ensure the users.txt file exists with usernames and passwords.

    Create a folder named server_files in the same directory.

    Run the server:

    python server.py

Client

    Create a folder named client_files for downloads.

    Run the client:

    python client.py

    Follow the prompts to authenticate or register a new user.

    Use the chat commands as needed.

Security Notes

    Passwords are stored in plaintext in users.txt; this should be improved with hashing for production.


    Network communication is limited to localhost (127.0.0.1) by default.
