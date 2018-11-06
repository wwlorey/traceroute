from socket import *
import socket
import os
import sys
import struct
import time
import select


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

 
def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    
    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff
        
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    ID = os.getpid() & 0xFFFF
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff    

    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    return packet


def resolve_name_from_ip(addr):
    try:
        return gethostbyaddr(addr)[0]

    except:
        return addr
    

def get_route(hostname):
    timeLeft = TIMEOUT

    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = socket.gethostbyname(hostname)

            # Make a raw socket named mySocket
            icmp =socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()

                if timeLeft <= 0:
                    print(" *\t*\t*\tRequest timed out.")
                    continue

                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []: # Timeout
                    print(" *\t*\t*\tRequest timed out.")

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print(" *\t*\t*\tRequest timed out.")

            except socket.timeout:
                continue
             
            else:
                # Fetch the icmp type from the IP packet                
                icmpHeader = recvPacket[20:28]
                types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d     rtt=%.0f ms    %s    %s" % (ttl, (timeReceived - t)*1000, addr[0], resolve_name_from_ip(addr[0])))
                     
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d     rtt=%.0f ms    %s    %s" % (ttl, (timeReceived - t)*1000, addr[0], resolve_name_from_ip(addr[0])))
                     
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d     rtt=%.0f ms    %s    %s" % (ttl, (timeReceived - t)*1000, addr[0], resolve_name_from_ip(addr[0])))
                    return

                else:
                    print("error")

                break
             
            finally:
                mySocket.close()


get_route("www.google.com")
# get_route("www.yahoo.com")
# get_route("www.mst.edu")
# get_route("www.williamlorey.com")
