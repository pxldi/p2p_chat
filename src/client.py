import socket
import tkinter as tk
import threading
import random
import string
import time
import json

class ChatClient:
    """ Initializes client with name, UDP port, server IP adress and server port.
    """
    def __init__(self, name: str, udp_port: int, server_host: str, server_port: int, message_callback = None):
        self.name = name
        self.server_host = server_host
        self.server_port = server_port
        self.message_callback = message_callback or print
        
        # Create sockets
        try:
            # Server communication socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # TCP listening socket for peer connections
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.bind(('', 0))
            self.tcp_port = self.tcp_socket.getsockname()[1]
            self.tcp_socket.listen()  # Start listening immediately
            
            # UDP socket for peer discovery
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(('', udp_port if udp_port != 0 else 0))
            self.udp_port = self.udp_socket.getsockname()[1]
            
            self.running = True  # Add flag to control threads
            self.peers = {}  # {name: (ip, udp_port)}
            self.chat_sessions = {}  # {name: tcp_socket}
            self.secrets = {}  # {peer_name: secret}
            
            # Start listening threads
            self.server_connect()
            threading.Thread(target=self.listen_udp, daemon=True).start()
            threading.Thread(target=self.listen_tcp, daemon=True).start()
            
        except Exception as e:
            self.cleanup()
            raise e
        
    def cleanup(self):
        """Clean up all sockets and resources"""
        self.running = False
        
        # Close all chat sessions
        for sock in self.chat_sessions.values():
            try:
                sock.close()
            except:
                pass
        self.chat_sessions.clear()
        # Close main sockets
        for sock in [self.server_socket, self.tcp_socket, self.udp_socket]:
            try:
                sock.close()
            except:
                pass

    def server_connect(self):
        """Connect to server and register client"""
        try:
            # Set keepalive options
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Windows-specific keepalive options
            if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                # On Windows, use the following values:
                # - keep idle: 1 second
                # - interval: 1 second
                # - retry count: 5
                self.server_socket.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 1000, 1000))
            
            self.server_socket.connect((self.server_host, self.server_port))
            
            # Send REGISTER message
            msg = f"REGISTER:{self.name}:{socket.gethostbyname(socket.gethostname())}:{self.udp_port}\r\n"
            self.server_socket.send(msg.encode())
            threading.Thread(target=self.handle_server, daemon=True).start()
        except socket.error as e:
            print(f"Failed to connect to server: {e}")
            self.cleanup()
            raise
    
    def handle_server(self):
        """Handle incoming server messages"""
        buffer = ""
        while self.running:  # Changed from True to self.running
            try:
                data = self.server_socket.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                while "\r\n" in buffer:
                    msg, buffer = buffer.split("\r\n", 1)
                    parts = msg.split(":")
                    
                    if parts[0] == "LIST":
                        # Process user list
                        for i in range(1, len(parts), 3):
                            name, ip, port = parts[i:i+3]
                            self.peers[name] = (ip, int(port))
                    
                    elif parts[0] == "UPDATE":
                        action, name, ip, port = parts[1:]
                        if action == "JOIN":
                            self.peers[name] = (ip, int(port))
                            self.message_callback(f"System", f"{name} joined the chat")
                        elif action == "LEAVE":
                            self.peers.pop(name, None)
                            self.message_callback(f"System", f"{name} left the chat")
                    
                    elif parts[0] == "BROADCAST":
                        name, length, message = parts[1:]
                        self.message_callback(f"{name} (Broadcast)", message)
                    
                    elif parts[0] == "ERROR":
                        length, message = parts[1:]
                        self.message_callback("Error", message)
            
            except socket.error:
                break
    
    def listen_udp(self):
        """Listen for UDP chat initiation requests"""
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message["type"] == "tcp_port_info":
                    peer_username = message["username"]
                    peer_tcp_port = message["tcp_port"]
                    self.message_callback("System", f"Received connection info from {peer_username}")
                    self.connect_to_peer(addr[0], peer_tcp_port)
                    
            except json.JSONDecodeError:
                self.message_callback("Error", "Received invalid UDP message")
            except socket.error as e:
                if self.running:
                    self.message_callback("System", f"UDP Error: {e}")
                continue
    
    def listen_tcp(self):
        """Listen for incoming TCP chat connections"""
        while self.running:
            try:
                client_sock, addr = self.tcp_socket.accept()
                
                peer_name = client_sock.recv(1024).decode()
                client_sock.send(self.name.encode())

                self.chat_sessions[peer_name] = client_sock
                
                threading.Thread(
                    target=self.handle_chat_session,
                    args=(peer_name, client_sock),
                    daemon=True
                ).start()
            except socket.error as e:
                if self.running:  # Only log error if we're still meant to be running
                    print(f"TCP Listen Error: {e}")
                continue
    
    def handle_chat_session(self, peer_name: str, sock: socket.socket):
        """Handle messages for a specific chat session"""
        try:
            while self.running:
                data = sock.recv(1024).decode()
                if not data:
                    break
                self.message_callback(peer_name, data)
                
        except socket.error as e:
            self.message_callback("System", f"Lost connection to {peer_name}: {e}")
        finally:
            sock.close()
            if peer_name in self.chat_sessions:
                del self.chat_sessions[peer_name]
            self.message_callback("System", f"Chat session with {peer_name} ended")

    def connect_to_peer(self, peer_ip: str, peer_tcp_port: int):
        """Create TCP connection to peer"""
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_ip, int(peer_tcp_port)))
            
            # Send our username first
            peer_socket.send(self.name.encode())
            
            # Receive peer's username
            peer_name = peer_socket.recv(1024).decode()
            
            if peer_name:
                self.chat_sessions[peer_name] = peer_socket
                self.message_callback("System", f"Connected to {peer_name}")
                
                # Start message handler thread
                threading.Thread(target=self.handle_chat_session, 
                            args=(peer_name, peer_socket),
                            daemon=True).start()
        except Exception as e:
            self.message_callback("Error", f"Failed to connect to peer: {e}")
    
    #def start_chat(self, peer_name: str):
    #    """Initiate chat with a peer"""
    #    if peer_name not in self.peers:
    #        self.message_callback("System", f"Unknown peer: {peer_name}")
    #        return
    #        
    #    if peer_name in self.chat_sessions:
    #        self.message_callback("System", f"Chat session already exists with {peer_name}")
    #        return
    #        
    #    peer_ip, peer_udp_port = self.peers[peer_name]
    #    self.message_callback("System", f"Attempting to connect to {peer_name} at {peer_ip}:{peer_udp_port}")
    #    
    #    # Generate random secret
    #    secret = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    #    self.secrets[peer_name] = secret
    #    
    #    # Send UDP initialization
    #    msg = f"INIT:{secret}:{self.tcp_port}\r\n"
    #    try:
    #        # Make sure peer_udp_port is an integer
    #        port = int(peer_udp_port)
    #        self.message_callback("System", f"Sending UDP init to {peer_ip}:{port}")
    #        self.udp_socket.sendto(msg.encode(), (peer_ip, port))
    #    except socket.error as e:
    #        self.message_callback("Error", f"Failed to send chat initiation: {e}")
    #        # Clean up secret if failed
    #        if peer_name in self.secrets:
    #            del self.secrets[peer_name]

    def start_chat(self, peer_name: str):
        """Start chat with a peer using UDP discovery"""
        if peer_name not in self.peers:
            self.message_callback("System", f"Unknown peer: {peer_name}")
            return
            
        if peer_name in self.chat_sessions:
            self.message_callback("System", f"Chat session already exists with {peer_name}")
            return
            
        peer_ip, peer_udp_port = self.peers[peer_name]
        
        # Send TCP port info via UDP
        message = {
            "type": "tcp_port_info",
            "username": self.name,
            "tcp_port": self.tcp_port
        }
        
        try:
            self.udp_socket.sendto(json.dumps(message).encode(), (peer_ip, int(peer_udp_port)))
            self.message_callback("System", f"Sent connection request to {peer_name}")
        except Exception as e:
            self.message_callback("Error", f"Failed to send connection request: {e}")

    def send_chat(self, peer_name: str, message: str):
        """Send chat message to peer"""
        if peer_name not in self.chat_sessions:
            self.message_callback("System", f"No active chat session with {peer_name}")
            return False
            
        try:
            self.chat_sessions[peer_name].send(message.encode())
            return True
        except socket.error as e:
            self.message_callback("Error", f"Failed to send message: {e}")
            # Close failed session
            if peer_name in self.chat_sessions:
                self.chat_sessions[peer_name].close()
                del self.chat_sessions[peer_name]
            return False
    
    def broadcast(self, message: str):
        """Send broadcast message via server"""
        msg = f"BROADCAST:{self.name}:{len(message)}:{message}\r\n"
        try:
            self.server_socket.send(msg.encode())
        except socket.error as e:
            print(f"Failed to send broadcast: {e}")

    def disconnect(self):
        """Clean disconnect from server and peers"""
        try:
            self.server_socket.send("QUIT\r\n".encode())
        except:
            pass
        finally:
            self.cleanup()


class ChatClientGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("P2P Chat")
        self.client = None
        self.create_widgets()

    def create_widgets(self):
        # Server connection frame
        conn_frame = tk.Frame(self.window)
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(conn_frame, text="Name:").pack(side=tk.LEFT)
        self.name_entry = tk.Entry(conn_frame, width=15)
        self.name_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Server:").pack(side=tk.LEFT)
        self.server_entry = tk.Entry(conn_frame, width=15)
        self.server_entry.insert(0, "localhost")
        self.server_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, "12345")
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.connect_btn = tk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        # Main content area
        content = tk.Frame(self.window)
        content.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Users list
        users_frame = tk.LabelFrame(content, text="Online Users")
        users_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        self.users_list = tk.Listbox(users_frame, width=20, height=20)
        self.users_list.pack(padx=5, pady=5)
        self.users_list.bind('<Double-Button-1>', self.start_chat)

        # Chat area
        chat_frame = tk.LabelFrame(content, text="Chat")
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.chat_log = tk.Text(chat_frame, height=20)
        self.chat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Message input
        input_frame = tk.Frame(chat_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind('<Return>', self.send_message)

        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT, padx=5)

        self.broadcast_btn = tk.Button(input_frame, text="Broadcast", command=self.send_broadcast)
        self.broadcast_btn.pack(side=tk.LEFT)

    def toggle_connection(self):
        if self.client is None:
            try:
                name = self.name_entry.get().strip()
                server = self.server_entry.get().strip()
                port = int(self.port_entry.get().strip())

                if not name:
                    self.show_message("System", "Please enter a name")
                    return

                self.client = ChatClient(name, 0, server, port, 
                                    message_callback=self.show_message)  # Pass callback
                self.connect_btn.config(text="Disconnect")
                self.update_users_list()
                threading.Thread(target=self.update_loop, daemon=True).start()

            except Exception as e:
                self.show_message("Error", str(e))
                self.client = None

    def update_loop(self):
        while self.client:
            self.update_users_list()
            time.sleep(1)

    def update_users_list(self):
        # Save selection
        selection = self.users_list.curselection()
        selected_name = None
        if selection:
            selected_name = self.users_list.get(selection[0])

        # Rebuild list
        self.users_list.delete(0, tk.END)
        sorted_peers = sorted(self.client.peers.keys())
        for peer in sorted_peers:
            self.users_list.insert(tk.END, peer)

        # Restore selection if still present
        if selected_name in sorted_peers:
            idx = sorted_peers.index(selected_name)
            self.users_list.select_set(idx)
            self.users_list.activate(idx)

    def start_chat(self, event=None):
        if not self.client:
            return
        selection = self.users_list.curselection()
        if selection:
            peer = self.users_list.get(selection[0])
            self.client.start_chat(peer)
            self.show_message("System", f"Starting chat with {peer}")

    def send_message(self, event=None):
        if not self.client:
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return

        selection = self.users_list.curselection()
        if not selection:
            self.show_message("System", "Select a user first")
            return

        peer = self.users_list.get(selection[0])
        if peer not in self.client.chat_sessions:
            self.show_message("System", f"No active chat session with {peer}, starting one...")
            self.client.start_chat(peer)
            # Give a small delay for connection to establish
            time.sleep(0.5)
        
        try:
            self.client.send_chat(peer, msg)
            self.show_message(self.client.name, msg)
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self.show_message("Error", f"Failed to send message: {e}")

    def send_broadcast(self):
        if not self.client:
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return

        self.client.broadcast(msg)
        self.show_message(f"{self.client.name} (Broadcast)", msg)
        self.msg_entry.delete(0, tk.END)

    def show_message(self, sender, message):
        self.chat_log.insert(tk.END, f"{sender}: {message}\n")
        self.chat_log.see(tk.END)

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    gui = ChatClientGUI()
    gui.run()