import socket
import tkinter as tk
from tkinter import ttk
import threading

class ChatServer:
    """ Initializes server with given tcp port and sets initial variables.
    """
    def __init__(self, host='localhost', tcp_port=12345):
        self.host = host
        self.tcp_port = tcp_port
        self.stop_flag = False
        self.clients = {}
        socket.setdefaulttimeout(30)

    def add_client(self, name: str, ip: str, port: int) -> bool:
        """Add a client with unqiue name and their ip
        and port to the server.
        
        Args:
            name: Client identifier
            ip: Client IP address 
            port: Client port number

        Returns:
            bool: True if client added, False if name exists
        """
        if name in self.clients: return False
        self.clients[name] = (ip, port)
        return True

    def listen_for_connections(self):
        """Listen for and accept incoming TCP connections.

        Creates server socket, binds to host/port, and accepts client connections.
        Spawns new thread to handle each client. Continues until stop_flag is set.
        Handles socket timeout by continuing loop.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.tcp_port))
            server_socket.listen()
            while not self.stop_flag:
                try:
                    client_socket, (client_ip, _) = server_socket.accept()
                    threading.Thread(target=self.handle_client, args=(client_socket, client_ip))
                except socket.timeout:
                    continue

    def handle_client(self, client_socket: socket.socket, client_ip: str):
        """Handle client registration and message routing.

        Registers client if not present. Sends current list to new client as 'CURRENT_LIST,name,ip,port'.
        Broadcasts addition of the client as 'NEW_CLIENT,name,ip,port'. It handles broadcast messages as
        'BROADCAST,name,message' and handles quitting of clients by removing the client and broadcasting
        as 'QUIT,name'.
        """
        try:
            data = client_socket.recv(1024)
            name, udp_port = data.split(",")

            if self.add_client(name, client_ip, udp_port):
                client_list = ",".join(f"{name},{ip},{port}"
                                    for name, (ip, port) in self.clients.items())
                client_socket.send(f"CURRENT_LIST,{client_list}".encode())
                self.broadcast(f"NEW_CLIENT,{name},{client_ip},{udp_port}")

                while not self.stop_flag:
                    msg = client_socket.recv(1024)
                    broadcast_code = "BROADCAST"
                    if msg.startswith(broadcast_code):
                        self.broadcast(f"BROADCAST,{name},{msg[len(broadcast_code)+1:]}")
                    elif msg == "QUIT":
                        break
        except socket.error:
            pass
        finally:
            if name in self.clients:
                del self.clients[name]
                self.broadcast(f"QUIT,{name}")
            client_socket.close()

    def broadcast(self, message: str):
        """Send message to all currently connected clients
        """
        for _, (ip, port) in self.clients.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                    server_socket.connect((ip, port))
                    server_socket.send(message.encode())
            except socket.error:
                pass

class ChatServerGUI:
    def __init__(self):
        self.server = ChatServer()
        self.window = tk.Tk()
        self.window.title("ChatServer")
        self.create_widgets()

    def create_widgets(self):
        self.start_button = tk.Button(self.window, text="Start Server", command=self.toggle_server)
        self.start_button.pack(pady=5)
        self.clients_list = tk.Listbox(self.window, height=10, width=40)
        self.clients_list.pack(pady=5)
        self.update_clients_list()

    def update_clients_list(self):
        self.clients_list.delete(0, tk.END)
        for name, (ip, port) in self.server.clients.items():
            self.clients_list.insert(tk.END, f"{name}: {ip}:{port}")
        self.window.after(1000, self.update_clients_list)

    def toggle_server(self):
        if self.start_button["text"] == "Start Server":
            threading.Thread(target=self.server.listen_for_connections).start()
            self.server.stop_flag = False
            self.start_button["text"] = "Stop Server"
        else:
            self.server.stop_flag = True
            self.start_button["text"] = "Start Server"

if __name__ == "__main__":
    gui = ChatServerGUI()
    gui.window.mainloop()
