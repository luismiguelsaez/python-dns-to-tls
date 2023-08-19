import sys
import socket
import threading
import ssl
import logging
from os import getenv as osgetenv
from select import select

BUFFER_SIZE = 1024

# Handle the client connection
def tcpClientHandler(clientSocket: socket.socket)->None:

  # Read the data from the client oppened socket
  requestData = clientSocket.recv(BUFFER_SIZE)
  logger.debug("Got request data from TCP connection: {}".format(requestData))

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

  logger.debug("Connecting to upstream server {}:{} - '{}'".format(serverIP, serverPort, query))

  # Create SSL context, enforcing TLS 1.2 as protocol
  try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_verify_locations('/etc/ssl/cert.pem')
    context.check_hostname = True
  except Exception as sslConExc:
    logger.exception("Error while creating SSL context: {}".format(sslConExc))
    errCode = 1

  # Wrap the socket so it is encapsulated in an SSL connection
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with context.wrap_socket(sock=sock,server_hostname=serverIP) as ssock:
      try:
        ssock.connect(server)
        logger.debug("Sending query to upstream server {} - '{}'".format(ssock.server_hostname, query))
        ssock.send(query)
      except ssl.SSLCertVerificationError as sslCertVerifyExc:
        logger.exception("Error while verifying upstream server certificate [{}:{}]: {}".format(serverIP, serverPort, sslCertVerifyExc))
        errCode = 2
      except Exception as exc:
        logger.exception("Error while connecting to upstream DNS server [{}:{}]: {}".format(serverIP, serverPort, exc))
        errCode = 1
      finally:
        logger.debug("Waiting for data from upstream server {}:{}".format(serverIP, serverPort))
        data = ssock.recv(1024)
        logger.debug("Got data from upstream server {}:{} - '{}'".format(serverIP, serverPort, data))
  
  return errCode, data


# Look for environment variables and set default values
bindIP = osgetenv("BIND_IP", "127.0.0.1")
bindPort = osgetenv("BIND_PORT", "2553")
upstreamDNSServer = osgetenv("UPSTREAM_DNS_SERVER", "1.1.1.1")
upstreamDNSPort = osgetenv("UPSTREAM_DNS_PORT", "853")
logLevel = osgetenv("LOG_LEVEL", "INFO").upper()

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
    
    select([UDPServerSocket, TCPServerSocket], [], [])
    #udpMessage, udpAddress = UDPServerSocket.recvfrom(1024)

    # Accept connections and create a thread for each one, calling to the client handler function
    # This covers the bonus point to handle several concurrent requests
    
    if TCPServerSocket in select([UDPServerSocket, TCPServerSocket], [], [])[0]:
      conn, addr = TCPServerSocket.accept()
      logger.debug("TCP client connected: {}".format(addr))
      threading.Thread(target=tcpClientHandler, args=(conn,)).start()
    
    if UDPServerSocket in select([UDPServerSocket, TCPServerSocket], [], [])[0]:
      data, addr = UDPServerSocket.recvfrom(BUFFER_SIZE)
      logger.debug("UDP client connected: {}, data: {}".format(addr, data.decode('utf-8')))
      upstreamQueryErr, upstreamServerData = upstreamTLSSendQuery(upstreamDNSServer, int(upstreamDNSPort), data)
      if upstreamQueryErr == 0:
        logger.debug("Sending data to client: {} - '{}'".format(addr, upstreamServerData))
        UDPServerSocket.sendto(upstreamServerData, addr)
      else:
        logger.error("Error while connecting to upstream DNS server")



if __name__ == "__main__":
  main()
