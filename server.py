import os
import socket
import threading
import rsa


class SecureChatServer:
    def __init__(self, host, port):
        """
        Initialize the SecureChatServer class.

        Parameters:
        - host (str): The server's hostname.
        - port (int): The port number for the server.
        """
        self.HOST = host
        self.PORT = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}  # Dictionary to store client data (socket, public_key)

    def start(self):
        """
        Start the server and handle incoming connections.
        """
        with self.server_socket as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            print(f"Server listening on {self.HOST}:{self.PORT}")

            try:
                while True:
                    client_socket, addr = s.accept()
                    self.handle_new_client(client_socket, addr)
            except Exception as server_error:
                print(f"Server error: {str(server_error)}")

    def handle_new_client(self, client_socket, addr):
        """
        Handle a new client connection.

        Parameters:
        - client_socket (socket): The client's socket.
        - addr (tuple): The client's address (IP, port).
        """

        # Send server's public key to the client
        client_socket.send(self.public_key.save_pkcs1("PEM"))
        client_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))

        # Receive the username and authenticate the user
        username = rsa.decrypt(client_socket.recv(1024), self.private_key).decode()
        print(f"Accepted connection from {username} at {addr}")

        # Authenticate the user
        if self.user_check(username):
            client_socket.send(rsa.encrypt("user.e".encode(), client_public_key))
            print("user_exists")
            password = rsa.decrypt(client_socket.recv(1024), self.private_key).decode()
            if self.authenticator(username, password):
                    # Notify the client that authentication is successful
                    client_socket.send(rsa.encrypt("yes.auth".encode(), client_public_key))

                    self.clients[username] = {"socket": client_socket, "public_key": client_public_key}
                    client_socket.send(rsa.encrypt("You are connected.".encode(), client_public_key))

                    # Start a new thread to handle the client
                    client_thread = threading.Thread(target=self.handle_client, args=(username,))
                    client_thread.start()
            else:
                # Notify the client that authentication failed
                client_socket.send(rsa.encrypt("no.auth".encode(), client_public_key))
                print(f"Authentication failed for {username}. Closing connection.")
                client_socket.close()
        else:
            client_socket.send(rsa.encrypt("user.dne".encode(), client_public_key))
            password = rsa.decrypt(client_socket.recv(1024), self.private_key).decode()
            self.add_user(username, password)
            self.clients[username] = {"socket": client_socket, "public_key": client_public_key}
            client_socket.send(rsa.encrypt("You are connected.".encode(), client_public_key))
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=self.handle_client, args=(username,))
            client_thread.start()
    

    def list_files(self):
        """
        List all files available on the server.

        Returns:
        - files (list): List of filenames available on the server.
        """
        files = os.listdir("server_files")
        return files


    def handle_client(self, username):
        """
        Handle communication with a client.

        This method manages communication between the server and a specific client identified by their username.

        Args:
            username (str): The username of the client being handled.

        Note:
            The communication includes receiving and sending messages, handling file transfers,
            and managing the disconnection process.
        """

        client_data = self.clients[username]
        client_socket = client_data["socket"]
        public_key = client_data["public_key"]

        try:
            while True:
                # Receive encrypted data from the client
                encrypted_data = client_socket.recv(1024)
                
                try:
                    # Attempt to decrypt the received data using the server's private key
                    decrypted_data = rsa.decrypt(encrypted_data, self.private_key)
                    data = decrypted_data.decode("utf-8")
                    print("Received encrypted message:", data)
                except rsa.DecryptionError:
                    # If decryption fails, treat the data as non-encrypted
                    data = encrypted_data.decode("utf-8")
                    print("Received non-encrypted message:", data)

                # Check for client exit command
                if data.lower() == "exit":
                    print(f"User {username} requested to exit. Connection with {username} closed.")
                    break

                # Process private messages
                if data[0] == "@":
                    recipient, message = data[1:].split(":", 1)
                    if recipient in self.clients:
                        recipient_data = self.clients[recipient]
                        recipient_socket = recipient_data["socket"]
                        recipient_public_key = recipient_data["public_key"]

                        # Encrypt the message with the recipient's public key
                        message = f"{username} (private): {message}\n"
                        recipient_socket.sendall(rsa.encrypt(message.encode(), recipient_public_key))
                    else:
                        client_socket.sendall(rsa.encrypt(f"User '{recipient}' not found.".encode(), public_key))
                else:
                    # Broadcast the received message to all clients
                    message = f"{username}: {data}\n"
                    for target_username, target_data in self.clients.items():
                        target_socket = target_data["socket"]
                        target_socket.sendall(rsa.encrypt(message.encode(), target_data["public_key"]))

                # Handle file transfer from client to server
                if data.startswith(".file"):
                    file_path = data.split(" ")[1]

                    file = open(f"server_files/server_{file_path}", 'wb')
                    try:
                        print("Receiving...")
                        
                        while True:
                            data_chunk = client_socket.recv(1024)  
                            if not data_chunk:
                                break
                            if data_chunk.endswith(b"<END>"):
                                file.write(data_chunk[:-len(b"<END>")])
                                break
                            file.write(data_chunk)

                        print("Done Receiving")
                        client_socket.send('File received successfully.'.encode())
                    except Exception as e:
                        print(f"Error receiving file: {e}")
                    finally:
                        file.close()

                # Send a list of available files to the client
                if data.lower() == ".list_files":
                    files = self.list_files()
                    files_list = "\n".join(files)
                    client_socket.send(rsa.encrypt(files_list.encode(), public_key))

                # Handle file transfer from server to client
                if data.startswith(".download"):
                    file_path = data.split(" ")[1]
                    try:
                        with open(f"server_files/{file_path}", "rb") as file:
                            print(f"Sending {file_path}...")
                            chunk_size = 1024 

                            while True:
                                data = file.read(chunk_size)
                                if not data:
                                    client_socket.send(b"<END>") 
                                    break
                                client_socket.send(data)
                            
                        print(f"{file_path} sent successfully.")
                    except Exception as e:
                        print(f"Error sending file: {e}")

        except Exception as client_error:
            print(f"Error with {username}: {client_error}")
        finally:
            # Clean up when the client disconnects
            client_socket.close()
            del self.clients[username]


    def user_check(self, username):
        """ Check if the user exist in our users.txt file"""
        with open("users.txt", "r") as file:
            #loop over all lines assigning usercheck and pswd check to each username and password it splits on
            for line in file:
                usercheck, pswdcheck = line.strip().split(":")
                if usercheck == username:
                    return True
        return False


    def add_user(self, username, password):
        """ Add a user if the user does not exist in our users.txt file"""
        #open users.txt in edit mode
        with open ("users.txt", "a") as file: 
            file.write(f"\n{username}:{password}")


    def authenticator(self, username, password):
        """ Check if the user's password matched the one stored in the users.txt """
        with open ("users.txt", "r") as file:
            for line in file:
                usercheck, pswdcheck = line.strip().split(":")
                if usercheck == username and pswdcheck == password: 
                    return True
        return False 
    

if __name__ == "__main__":
    public_key, private_key = rsa.newkeys(1024)

    # Create an instance of the server and start it
    server = SecureChatServer("127.0.0.1", 65345)
    server.public_key = public_key
    server.private_key = private_key
    server.start()
