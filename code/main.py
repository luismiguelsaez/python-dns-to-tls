import sys
import socket
import threading
import ssl
import logging
from os import environ

# Handle the client connection
def tcpClientHandler(clientSocket:socket.socket):

  # Read the data from the client oppened socket
  requestData = clientSocket.recv(1024)
  logger.debug("Got request data: {}".format(requestData))

  # Call to the function which send the request to the upstream DSN over TLS server
  upstreamQueryErr, upstreamServerData = upstreamTLSSendQuery(upstreamDNSServer, int(upstreamDNSPort), requestData)

  # Send the data from the upstream DNS server back to the client as response
  if upstreamQueryErr == 0:
    clientSocket.send(upstreamServerData)
    clientSocket.close()
    logger.debug("Connection closed")
  else:
    clientSocket.close()
    logger.error("Error while connecting to upstream DNS server")

# Send data to the upstream DNS over TLS server
def upstreamTLSSendQuery(serverIP:str, serverPort:int, query:bytes)->bytes:

  errCode = 0

  server = (serverIP, serverPort)

  # Create SSL context, enforcing TLS 1.2 as protocol
  try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_verify_locations('/etc/ssl/cert.pem')
    context.check_hostname = False
  except Exception as sslConExc:
    logger.exception("Error while creating SSL context: {}".format(sslConExc))
    errCode = 1

  # Wrap the socket so it is encapsulated in an SSL connection
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
      with context.wrap_socket(sock=sock) as ssock:
        ssock.connect(server)
        ssock.send(query)
        data = ssock.recv(1024)
  except Exception as exc:
    logger.exception("Error while connecting to upstream DNS server [{}{}]: {}".format(serverIP, serverPort, exc))
    errCode = 1

  return errCode, data

# Look for environment variables and set default values
bindIP = "127.0.0.1" if "BIND_IP" not in environ else environ["BIND_IP"]
bindPort = "2553" if "BIND_PORT" not in environ else environ["BIND_PORT"]
upstreamDNSServer = "1.1.1.1" if "UPSTREAM_DNS_SERVER" not in environ else environ["UPSTREAM_DNS_SERVER"]
upstreamDNSPort = "853" if "UPSTREAM_DNS_PORT" not in environ else environ["UPSTREAM_DNS_PORT"]
logLevel = "INFO" if "LOG_LEVEL" not in environ else environ["LOG_LEVEL"].upper()

# Add logger and set level from variable
logFormat = "%(levelname)s %(asctime)s - %(message)s"

logging.basicConfig(
                    stream = sys.stdout, 
                    format = logFormat, 
                    level = logLevel
                    )

logger = logging.getLogger()


def main():

  # Create sockets
  UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
  TCPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
  TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

  # Bind sockets
  try:
    UDPServerSocket.bind((bindIP, int(bindPort)))
    TCPServerSocket.bind((bindIP, int(bindPort)))
    TCPServerSocket.listen()
  except Exception:
    logger.exception("Failed to bind socket {}:{}".format(bindIP,bindPort))

  logger.info("Server listening on {}:{}".format(bindIP,bindPort))

  # Handle incoming connections in a loop
  while(True):
    
    #udpMessage, udpAddress = UDPServerSocket.recvfrom(1024)

    # Accept connections and create a thread for each one, calling to the client handler function
    # This cover the bonus point to handle several concurrent requests
    conn, addr = TCPServerSocket.accept()
    logger.debug("Client connected: {}".format(addr))
    client_handler = threading.Thread(target = tcpClientHandler, args=(conn,))
    client_handler.start()



if __name__ == "__main__":
  main()
