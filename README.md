

## Build

```bash
docker build -t dnsproxy:latest .
```

## Run

```bash
docker run --name dnsproxy -d -p 2553:2553 -e LOG_LEVEL=DEBUG -e BIND_IP=0.0.0.0 dnsproxy:latest
```

## Test

```bash
dig -p 2553 @127.0.0.1 www.google.com +tcp +short
python code/test/client.py
```

## Comments

- I could have used `socketserver`, that implements a higher level server, but I found more funny to go with `socket`
- Added a small script in `code/test` folder, that can be implemented as part of the server testing stage in the CICD pipeline
- Added some comments in the code
- The `wrap_socket` being used initially hasn't SNI support
- Added a simple GH actions workflox to build and push the image to DocherHub

## Answers to questions

1. Security concerns while deploying the solution
  
  - Although the connection between the service and the upstreadm DNS over TLS server, traffic could still be captured between the DNS client and the proxy service

2. I can think in two different implementations
  
  - DNS proxy as a sidecar for the service that is going to use it, so we can avoid the possibility of the traffict client->proxy to be intercepted
  - A service to be consumed from different services in the infrastructure. In that case, as the traffic would be higher, I would implement a caching solution based on Redis, for instance, which can handle TTL easily

3. Improvements

  - Possibility to use a cache for the queries, reducing the requests to the upstream DNS over TLS server and the response times substantially

