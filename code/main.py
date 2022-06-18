import sys
import socket
import threading
import ssl
import logging
from os import environ


def clientHandler(clientSocket:socket.socket):

  requestData = clientSocket.recv(1024)
  logger.debug("Got request data: {}".format(requestData))

  upstreamServerData = upstreamTLSSendQuery(upstreamDNSServer, int(upstreamDNSPort), requestData)

  clientSocket.send(upstreamServerData)

  clientSocket.close()
  logger.debug("Connection closed")


def upstreamTLSSendQuery(serverIP:str, serverPort:int, query:bytes)->bytes:

  server = (serverIP, serverPort)

  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context.load_verify_locations('/etc/ssl/cert.pem')
  context.check_hostname = False

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with context.wrap_socket(sock) as ssock:
      ssock.connect(server)
      ssock.send(query)
      data = ssock.recv(1024)

  return data


def upstreamSendQuery(serverIP:str, serverPort:int, query:bytes)->bytes:

  server = (serverIP, serverPort)
  
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(server)
  sock.send(query)  	
  data = sock.recv(1024)

  return data

bindIP = "127.0.0.1" if "BIND_IP" not in environ else environ["BIND_IP"]
bindPort = "2553" if "BIND_PORT" not in environ else environ["BIND_PORT"]
upstreamDNSServer = "1.1.1.1" if "UPSTREAM_DNS_SERVER" not in environ else environ["UPSTREAM_DNS_SERVER"]
upstreamDNSPort = "853" if "UPSTREAM_DNS_PORT" not in environ else environ["UPSTREAM_DNS_PORT"]
logLevel = "INFO" if "LOG_LEVEL" not in environ else environ["LOG_LEVEL"]

logFormat = "%(levelname)s %(asctime)s - %(message)s"

logging.basicConfig(
                    stream = sys.stdout, 
                    format = logFormat, 
                    level = logLevel
                    )
    
logger = logging.getLogger()

def main():

  # Create sockets
  #UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
  TCPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

  try:
    TCPServerSocket.bind((bindIP, int(bindPort)))
    TCPServerSocket.listen()
  except Exception:
    logger.exception("Failed to bind socket {}:{}".format(bindIP,bindPort))

  logger.info("Server listening on {}:{}".format(bindIP,bindPort))

  # Handle incoming connections
  while(True):
      
    conn, addr = TCPServerSocket.accept()
    logger.debug("Client connected: {}".format(addr))
    client_handler = threading.Thread(target = clientHandler, args=(conn,))
    client_handler.start()

  TCPServerSocket.close()


if __name__ == "__main__":
  main()
