import socket
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import logging
from datetime import datetime

class ChatServer:
    """ Initializes server with given tcp port and sets initial variables.
    """
    def __init__(self, host='localhost', tcp_port=12345):
        self.host = host
        self.tcp_port = tcp_port
        self.stop_flag = False
        self.clients = {}
        self.logger = logging.getLogger("ChatServer")
        #socket.setdefaulttimeout(30)

    def add_client(self, name: str, ip: str, udp_port: int, client_socket: socket.socket) -> bool:
        """Add a client with unqiue name and their ip
        and port including their socket to the server.
        
        Args:
            name: Client identifier
            ip: Client IP address 
            udp_port: Client port number
            client_socket: Client socket to send messages to

        Returns:
            bool: True if client added, False if name exists
        """
        if name in self.clients: return False
        self.clients[name] = (ip, udp_port, client_socket)
        self.logger.info(f"Added client: {name} ({ip}:{udp_port})")
        return True

    def start(self):
        """Listen for and accept incoming TCP connections.

        Creates server socket, binds to host/port, and accepts client connections.
        Spawns new thread to handle each client. Continues until stop_flag is set.
        Handles socket timeout by continuing loop.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                self.server_socket.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 1000, 1000))

            self.server_socket.bind((self.host, self.tcp_port))
            self.server_socket.listen()
            self.logger.info(f"Server started on {self.host}:{self.tcp_port}")

            while not self.stop_flag:
                try:
                    client_socket, (client_ip, _) = self.server_socket.accept()
                    threading.Thread(target=self.handle_client, 
                                  args=(client_socket, client_ip),
                                  daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {e}")

        except Exception as e:
                self.logger.error(f"Server error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the server and clean up"""
        self.stop_flag = True
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        for _, (_, _, sock) in self.clients.items():
            try:
                sock.close()
            except:
                pass
        self.clients.clear()
        self.logger.info("Server stopped")

    def handle_client(self, client_socket: socket.socket, client_ip: str):
        """Handle client registration and message routing.

        Registers client if not present. Sends current list to new client as 'CURRENT_LIST,name,ip,port'.
        Broadcasts addition of the client as 'NEW_CLIENT,name,ip,port'. It handles broadcast messages as
        'BROADCAST,name,message' and handles quitting of clients by removing the client and broadcasting
        as 'QUIT,name'.

        Args:
            client_socket: Socket to receive client data
            client_ip: Client IP adress
        """
        client_name = None
        buffer = ""
        
        try:
            while not self.stop_flag:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                while "\r\n" in buffer:
                    msg, buffer = buffer.split("\r\n", 1)
                    parts = msg.split(":")
                    
                    if not parts:
                        continue
                    
                    command = parts[0]
                    
                    if command == "REGISTER":
                        if len(parts) != 4:
                            self.send_error(client_socket, "Invalid registration format")
                            continue
                            
                        name, ip, udp_port = parts[1:]
                        if not self.add_client(name, ip, int(udp_port), client_socket):
                            self.send_error(client_socket, "Nickname already taken")
                            continue
                        
                        client_name = name
                        # Send current user list
                        client_list = [f"{n}:{ip}:{p}" for n, (ip, p, _) in self.clients.items()]
                        self.send_client_list(client_socket, ":".join(client_list))
                        # Notify others
                        self.broadcast_update("JOIN", name, ip, udp_port)
                    
                    elif command == "BROADCAST":
                        if not client_name or len(parts) != 4:
                            self.send_error(client_socket, "Invalid broadcast format")
                            continue
                        
                        _, length, message = parts[1:]
                        if len(message) != int(length):
                            self.send_error(client_socket, "Message length mismatch")
                            continue
                        
                        self.broadcast_message(client_name, message)
                    
                    elif command == "QUIT":
                        break
        
        except socket.error as e:
            self.logger.error(f"Socket error with {client_name}: {e}")
        finally:
            if client_name and client_name in self.clients:
                ip, port, _ = self.clients[client_name]
                del self.clients[client_name]
                self.broadcast_update("LEAVE", client_name, ip, str(port))
            client_socket.close()

    def send_error(self, client_socket: socket.socket, message: str):
        """Send error message to specific client"""
        try:
            msg = f"ERROR:{len(message)}:{message}\r\n"
            client_socket.send(msg.encode())
        except socket.error as e:
            self.logger.error(f"Error sending error message: {e}")
    
    def send_client_list(self, client_socket: socket.socket, client_list: str):
        """Send current client list"""
        try:
            msg = f"LIST:{client_list}\r\n"
            client_socket.send(msg.encode())
        except socket.error as e:
            self.logger.error(f"Error sending client list: {e}")

    def broadcast_update(self, action: str, name: str, ip: str, port: str):
        """Send client update (JOIN/LEAVE) to all clients"""
        msg = f"UPDATE:{action}:{name}:{ip}:{port}\r\n"
        self.broadcast_raw(msg, exclude=name)

    def broadcast_message(self, sender: str, message: str):
        """Broadcast chat message to all clients"""
        msg = f"BROADCAST:{sender}:{len(message)}:{message}\r\n"
        self.broadcast_raw(msg)

    def broadcast_raw(self, message: str, exclude: str = None):
        """Send raw message to all clients except excluded one"""
        for name, (_, _, sock) in self.clients.items():
            if name != exclude:
                try:
                    sock.send(message.encode())
                except socket.error as e:
                    self.logger.error(f"Error broadcasting to {name}: {e}")

class ChatServerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Chat Server")
        self.window.geometry("800x600")

        self.server = ChatServer()
        self.setup_logging()
        self.create_widgets()

    def setup_logging(self):
        """Setup logging to both file and GUI"""
        self.log_queue = []
        
        class GUIHandler(logging.Handler):
            def __init__(self, callback):
                super().__init__()
                self.callback = callback
            
            def emit(self, record):
                self.callback(self.format(record))
        
        # Configure logging
        logger = logging.getLogger('ChatServer')
        logger.setLevel(logging.INFO)
        
        # GUI Handler
        gui_handler = GUIHandler(self.log_to_gui)
        gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(gui_handler)

    def create_widgets(self):
        # Create main container
        main_container = ttk.Frame(self.window, padding="5")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)

        # Server control frame
        control_frame = ttk.LabelFrame(main_container, text="Server Control", padding="5")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.status_label = ttk.Label(control_frame, text="Server Status: Stopped")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Server", command=self.toggle_server)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Client list frame
        clients_frame = ttk.LabelFrame(main_container, text="Connected Clients", padding="5")
        clients_frame.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(1, weight=1)
        
        self.clients_list = tk.Listbox(clients_frame)
        self.clients_list.pack(fill=tk.BOTH, expand=True)
        
        # Log frame
        log_frame = ttk.LabelFrame(main_container, text="Server Log", padding="5")
        log_frame.grid(row=1, column=1, sticky=(tk.N, tk.S, tk.E, tk.W))
        main_container.columnconfigure(1, weight=2)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Start periodic updates
        self.update_gui()

    def update_clients_list(self):
        self.clients_list.delete(0, tk.END)
        for name, (ip, port) in self.server.clients.items():
            self.clients_list.insert(tk.END, f"{name}: {ip}:{port}")
        self.window.after(1000, self.update_clients_list)

    def toggle_server(self):
        if self.start_button["text"] == "Start Server":
            self.server.stop_flag = False
            threading.Thread(target=self.server.start, daemon=True).start()
            self.start_button["text"] = "Stop Server"
            self.status_label["text"] = "Server Status: Running"
        else:
            self.server.stop()
            self.start_button["text"] = "Start Server"
            self.status_label["text"] = "Server Status: Stopped"

    def update_gui(self):
        """Update GUI elements periodically"""
        # Update clients list
        self.clients_list.delete(0, tk.END)
        for name, (ip, port, _) in self.server.clients.items():
            self.clients_list.insert(tk.END, f"{name} - {ip}:{port}")
        
        # Process any pending log messages
        while self.log_queue:
            msg = self.log_queue.pop(0)
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
        
        # Schedule next update
        self.window.after(1000, self.update_gui)

    def log_to_gui(self, message):
        """Add log message to queue for GUI display"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.append(f"{timestamp} - {message}")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    gui = ChatServerGUI()
    gui.run()
