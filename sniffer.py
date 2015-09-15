from _socket import inet_ntoa
import socket
import sys
import struct
import re
count = 0
http = 0
https =0
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565) #65565 kich thuoc bo dem
    except timeout:
        data = ''
    except:
        print "An error happened: "
        sys.exc_info()
    return data[0]

def getProtocol(protocolNr):
    protocolFile = open('Protocol.txt', 'r')#file chua kieu giao thuc
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n", "")
        protocol = protocol.replace(str(protocolNr), "")
        protocol = protocol.lstrip()
        return protocol

    else:
        return 'No such protocol.'

while count < 50:
    HOST = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    data = receiveData(s)

    unpackedDataIP = struct.unpack('!BBHHHBBH4s4s', data[0:20])
    version_IHL = unpackedDataIP[0]  # =69=0x45
    IHL = version_IHL & 0xF
    totalLength = unpackedDataIP[2]
    ID = unpackedDataIP[3]  # identification
    fragmentOffset = unpackedDataIP[4] & 0x1FFF

    protocolNr = unpackedDataIP[6]
    sourceAddress = inet_ntoa(unpackedDataIP[8])
    destinationAddress = inet_ntoa(unpackedDataIP[9])
    count += 1
    print "Package " + str(count)
    print "An IP packet with the size %i was captured." % (unpackedDataIP[2])
    print "Raw data: " + data
    print "\nParsed data"
    print "Header Length:\t\t" + str(IHL * 4) + " bytes"
    print "ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")"
    print "Length:\t\t\t" + str(totalLength)
    print "Protocol:\t\t" + getProtocol(protocolNr)
    if protocolNr == 6:
        print "Source:\t\t\t" + sourceAddress
        print "Destination:\t\t" + destinationAddress
        unpackedDataTCP = struct.unpack('!HH', data[20:24])
        destinationPort = unpackedDataTCP[1]
        sourcePort = unpackedDataTCP[0]
        print "destination Port: \t" + str(destinationPort)
        print "source Port: \t" + str(sourcePort)
        if destinationPort == 443 or sourcePort == 443:
            print "HTTPS!"
            https += 1
        if destinationPort == 80 or sourcePort == 80:
            print "HTTP!"
            http += 1
        print "End Parsed \t !!!!!!!!!!!!!!!!!! \n"
    else:
        print "cannot TCP"

    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

print " Amount capture package " + str(count)
print " Amount HTTP " + str(http)
print " Amount HTTPS " + str(https)