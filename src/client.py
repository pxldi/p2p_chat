import socket
import tkinter as tk
import threading

class ChatClient:
    """ Initializes client with name, UDP port, server IP adress and server port.
    """
    def __init__(self, name: str, udp_port: int, server_host: str, server_port: int):
        self.name = name
        self.udp_port = udp_port
        self.server_host = server_host
        self.server_port = server_port

        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.bind(('', 0)) # next free port
        self.tcp_port = self.tcp_socket.getsockname()[1]
        
        self.peers = {}
        self.chat_sessions = {}

        self.server_connect(server_host, server_port)

        self.udp_socket = socket.socket(socket.INET_AF, socket.SOCK_STREAM)
        self.udp_socket.bind(('', udp_port))
        threading.Thread(target=self.listen_udp).start()

    def server_connect(self, server_host: str, server_port: int):
        server = socket.socket(socket.INET_AF, socket.SOCK_STREAM)
        server.connect(server_host, server_port)
        server.send(f"{self.name},{self.udp_port}".encode())
        threading.Thread(target=self.handle_server, args=(server,)).start()
    
    def listen_udp(self):
        while True:
            data, addr = self.udp_socket.recvfrom(1024)
            msg = data.decode()
            if msg.startswith("CHAT_REQUEST"):
                _, peer_name, peer_tcp_port = msg.split(",")
                self.create_chat(peer_name, addr[0], int(peer_tcp_port))
    
    def create_chat(self, peer_name, peer_ip, peer_tcp_socket):
        sock = socket.socket(socket.INET_AF, socket.SOCK_STREAM)
        sock.connect((peer_ip, peer_tcp_socket))
        self.chat_sessions[peer_name] = sock 

    def start_chat(self, peer_name):
        peer_ip, peer_udp_port = self.peers[peer_name]
        msg = f"CHAT_REQUEST,{self.name},{self.tcp_port}"
        self.udp_socket.sendto(msg.encode(), (peer_ip, peer_udp_port))

class ChatClientGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("P2P Chat")
        self.