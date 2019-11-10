import sys
import socket
import struct
from easyzone import easyzone
from easyzone.zone_check import ZoneCheck
import ipaddress


types = { 1 : 'A' , 28 :'AAAA' , 2 : 'NS',  15 : 'MX' , 16 :'TXT', 6 : 'SOA', 5 : 'CNAME'}
root_ips = ['198.41.0.4', '192.228.79.201' , '192.33.4.12' , '199.7.91.13' , '192.203.230.10' ,
    '192.5.5.241' , '192.112.36.4' , '128.63.2.53' , '192.36.148.17' , '192.58.128.30' , '193.0.14.129' , '199.7.83.42' , '202.12.27.33']  
cache = {}

def enc(data , ind):
    name = ""
    while True:
        len = struct.unpack('!B' , data[ind:ind + 1])[0]
        ind += 1
        if(len == 0): break
        name = name + '.'
        if(len & (1<<7) != 0 and len & (1<<6) != 0):
            ind -= 1
            offset = struct.unpack('!H' , data[ind:ind + 2])[0]
            offset ^= (1<<15)
            offset ^= (1<<14)
            name += enc(data , offset)[0]
            ind += 2
            break
        for _ in range(0 , len):
            c = struct.unpack('!b' , data[ind:ind + 1])[0]
            name = name + chr(c)
            ind += 1
    return name[1:] , ind

def dec(name):
    res = b''
    l = name.split('.')
    for elem in l:
        if len(elem) == 0: continue
        res += struct.pack('!b' , len(elem))
        res += struct.pack( '!{}s'.format(len(elem)) , elem.encode('utf-8'))
    res += struct.pack('!b' , 0)
    return res

def getName(data , ind):
    name , ind = enc(data , ind)
    QTYPE , QCLASS = struct.unpack('!HH' , data[ind:ind + 4])
    ind += 4
    return name , QTYPE , QCLASS , ind

def decodeData(elem , QTYPE):
    res = b''
    if(QTYPE == 1):
        res = ipaddress.IPv4Address(elem).packed
    elif QTYPE == 28:
        res = ipaddress.IPv6Address(elem).packed
    elif QTYPE == 2:
        res = dec(elem)
    elif QTYPE == 15:
        res = struct.pack('!H' , elem[0]) +  dec(elem[1])
    elif QTYPE == 16:
        res = struct.pack('!b' , len(elem)) + elem.encode('utf-8')
    elif QTYPE == 6:
        l = elem.split(' ')
        for i in range(0 , 2): res += dec(l[i])
        for i in range(2 , 7): res += struct.pack('!I' , int(l[i]))
    elif QTYPE == 5:
        res = dec(elem)

    return res

def get_address(address , name , sock):
    answer = b''
    answer += struct.pack('!H' , 1)
    answer += struct.pack('!H' , 0)
    answer += struct.pack('!H' , 1)
    answer += struct.pack('!H' , 0)
    answer += struct.pack('!H' , 0)
    answer += struct.pack('!H' , 0)
    answer += dec(name)
    # print(name, dec(name) , address)
    answer += struct.pack('!H' , 1)
    answer += struct.pack('!H' , 1)

    sock.sendto(answer, address)
    data , _ = sock.recvfrom(4096)
    _ , _ , _ , ANCOUNT , NSCOUNT , ARCOUNT = struct.unpack("!HHHHHH" , data[:12])
    ind = len(answer)

    for _ in range(0 , ANCOUNT):
        _ , _ , _ , ind =  getName(data , ind)
        _ = struct.unpack("!I" , data[ind:ind + 4])[0]
        ind += 4
        rd = struct.unpack("!H" , data[ind:ind + 2])[0]
        ind += 2
        zero , first ,second , third = struct.unpack('!BBBB' , data[ind: ind + 4])
        add = (str(zero) + '.' + str(first) + '.' + str(second) + '.' + str(third) , 53)
        ind += + rd
        return add , data
    ns = ""
    for _ in range(0 , NSCOUNT):
        _ , _ , _ , ind =  getName(data , ind)
        _ = struct.unpack("!I" , data[ind:ind + 4])[0]
        ind += 4
        _ = struct.unpack("!H" , data[ind:ind + 2])[0]
        ind += 2
        ns , ind = enc(data  , ind)
    for _ in range(0 , ARCOUNT):
        _ , QTYPE , _ , ind =  getName(data , ind)
        _ = struct.unpack("!I" , data[ind:ind + 4])[0]
        ind += 4
        rd = struct.unpack("!H" , data[ind:ind + 2])[0]
        ind += 2
        if(QTYPE == 1):
            zero , first ,second , third = struct.unpack('!BBBB' , data[ind: ind + 4])
            add = (str(zero) + '.' + str(first) + '.' + str(second) + '.' + str(third) , 53)
            return  get_address(add , name , sock)
        ind += rd
    return get_address(get_address(('198.41.0.4', 53), ns , sock)[0] , name , sock)


def handle_request(data , QDCOUNT , CONFIG , id , options):
    ind = 12
    name , QTYPE , _ , ind = getName(data ,ind)
    answer = b''
    try :
        z = easyzone.zone_from_file(name,  CONFIG + 'example.com.conf')
        l = z.root.records(types[QTYPE]).items
        answer += struct.pack('!H' , id)
        answer += struct.pack('!H' , 33920)
        answer += struct.pack('!H' , 0)
        answer += struct.pack('!H' , len(l))
        answer += struct.pack('!H' , 0)
        answer += struct.pack('!H' , 0)
        for elem in l:
            answer += dec(name)       
            answer += struct.pack('!H' , QTYPE)
            answer += struct.pack('!H' , 1)
            answer += struct.pack('!I' , 0)
            res = decodeData(elem , QTYPE)
            answer += struct.pack('!H' , len(res))
            answer += res
    except: 
        if (name , QTYPE) in cache:
            return struct.pack("!H" , id) + cache[(name , QTYPE)][2:] 
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _ ,  res = get_address(('198.41.0.4' , 53) , name , sock) 
        cache[(name , QTYPE)] = struct.pack("!H" , id) + res[2:] 
        return struct.pack("!H" , id) + res[2:] 
    return answer


def run_dns_server(CONFIG, IP, PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((IP, int(PORT)))
    while True:
        data, address = sock.recvfrom(4096)
        id , options , QDCOUNT , _ , _  , _ = struct.unpack('!HHHHHH' , data[:12])
        send_data = bytes()
        if (options >> 15 == 0):
            send_data = handle_request(data , QDCOUNT , CONFIG , id , options)      

        if len(send_data) == 0: send_data = data  
        sent = sock.sendto(send_data, address)
        # print('sent {} bytes back to {}'.format(sent, address))
    
    # your code here
    pass

# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)