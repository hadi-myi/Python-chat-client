from codecs import utf_8_encode
import os
import socket
import threading
import rsa

HOST = "127.0.0.1"
PORT = 65345
public_key, private_key = rsa.newkeys(1024)
public_partner = None

# Client class
class Client:
    """Initialize the Client class."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.socket.connect((self.host, self.port))

    def send_message(self, message):
        self.socket.sendall(message)

    def receive_message(self):
        data = self.socket.recv(1024)
        return data

    def close(self):
        self.socket.close()

    def shutdown(self):
        """Shutdown the write end of the client's socket."""
        self.socket.shutdown(socket.SHUT_WR)


def receive_messages(client):
    """ Receive messages in a loop. used with threading.Thread() """
    while True:
        try: 
            response = rsa.decrypt(client.receive_message(), private_key).decode()
            if not response:
                break
            print(response)
        except:
            data = client.receive_message()


def connect():
    """Establish a connection between the client and the server."""
    client = Client(HOST, PORT)
    client.connect()       

    #receive public key from server
    public_partner = rsa.PublicKey.load_pkcs1(client.receive_message())
    client.send_message(public_key.save_pkcs1("PEM"))
    

    username = input("Type username: ")
    client.send_message(rsa.encrypt(username.encode(), public_partner))

    response = rsa.decrypt(client.receive_message(), private_key).decode()
    print(f"Server: {response}")
    if response == "user.dne":
        print("user does not exist.")
        password = input("Enter a new password: ")
        client.send_message(rsa.encrypt(password.encode(), public_partner))
       
    if response == "user.e":
        print("user Exists")
        password = input("Enter Your Password: ")
        client.send_message(rsa.encrypt(password.encode(), public_partner))

    response = rsa.decrypt(client.receive_message(), private_key).decode()
    
    if response == "yes.auth":
        print("Authenticated Successfully")
        
    if response == "no.auth":
        print("Wrong user/password. Closing Connection")
        client.close()
    
    
    # allows the client to receive messages from the server while also being able to send messages in the main thread.
    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    receive_thread.start()

    try:
        while True:
            message = input()
            client.send_message(rsa.encrypt(message.encode(), public_partner))
            # Display help information for available commands
            if message.lower() == ".help":
                print('''Type:
                    '.exit' to disconnect;
                    '.file filename.format' to send a file to the server;
                    '.list_files' to view what files are available to download from the server;
                    '.download filename.format' to download a file from the server''')
            
            # Exit the connection
            if message.lower() == ".exit":
                print("You have requested to exit. Closing the connection.")
                client.close()
                receive_thread.join()
                break
            
            # Send a file to the server
            if message.lower().startswith(".file"):
                requested_filename = message.split(" ")[1]
                
                try:
                    with open(requested_filename, "rb") as file:
                        print(f"Sending {requested_filename}...")
                        chunk_size = 1024 

                        while True:
                            data = file.read(chunk_size)
                            if not data:
                                client.send_message(b"<END>") 
                                break
                            client.send_message(data)
                        
                    print(f"{requested_filename} sent successfully.")
                except Exception as e:
                    print(f"Error sending {requested_filename}: {e}")

            # Request a list of available files from the server
            if message.lower() == ".list_files":
                files_list = rsa.decrypt(client.receive_message(), private_key).decode()
                print("Available files:")
                print(files_list)

            # Download a file from the server
            elif message.lower().startswith(".download"):
                # Get the name of the file to download
                requested_filename = message.split(" ")[1]
                with open(f"client_files/downloaded_{requested_filename}", 'wb') as file:
                    try:
                        print(f"Requesting {requested_filename}...")
                        print("Receiving...")
                        
                        while True:
                            file_data = client.receive_message()
                            if file_data.endswith(b"<END>"):
                                file.write(file_data[:-len(b"<END>")])
                                print(f"File {requested_filename} downloaded successfully.")
                                break
                            else:
                                file.write(file_data)
                    
                        print("Done Receiving")
                        client.send_message('File received successfully.'.encode())

                    except Exception as e:
                        print(f"Error receiving file: {e}")

    finally:
        client.close()
        receive_thread.join()


if __name__ == "__main__":
    connect()

