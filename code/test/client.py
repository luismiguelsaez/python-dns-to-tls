import dns.query
import dns.message

def main():
  dnsReqMsg = dns.message.make_query(qname="www.google.es",rdtype="A")
  dnsResMsg = dns.query.tcp(q=dnsReqMsg, where="127.0.0.1", port=2553)
  print(dnsResMsg)

if __name__ == "__main__":
  main()