import random
import socket
import sys
import threading
import time

if len(sys.argv) != 3:
    raise ValueError('unexpected input\nUsage: python <localIp> <ip expected>')

ip_extern = sys.argv[1]
expected_ip = sys.argv[2]
ip_amount_to_send = 25
ips = []
to_search = []
last_beat = 0
lock = threading.Lock()


# sock.settimeout(5)


def load_ips():
    global ips
    with lock:
        ips = []
        with open('ips', 'r') as file:
            for line in file.readlines():
                ips.append(line.replace('\n', '').replace('\r', ''))

    print(ips)


def add_ip(ip):
    global ips
    with lock:
        ips.append(ip)
        with open('ips', 'a') as file:
            file.write('\n' + ip)


def remove_ip(ip):
    global ips
    with lock:
        ips.remove(ip)
        with open('ips', 'w') as file:
            for ip in ips:
                file.write(ip + '\n')


# region dns

def get_flags(flags):
    b1 = bytes(flags[0:1])
    b2 = bytes(flags[1:2])

    qr = '1'
    opcode = ''
    for bit in range(1, 5):
        opcode += str(ord(b1) & (1 << bit))

    aa = '1'
    tc = '0'
    rd = '0'
    ra = '0'
    z = '000'
    rcode = '0000'

    return int(qr + opcode + aa + tc + rd, 2).to_bytes(1, byteorder='big') + \
           int(ra + z + rcode, 2).to_bytes(1, byteorder='big')


def build_question():
    qbytes = b''

    for part in expected_ip.split('.'):
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if not expected_ip.endswith('.'):
        qbytes += b'\x00'
    qbytes += b'\x00\x01'
    qbytes += b'\x00\x01'

    return qbytes


def rec_to_bytes(ttl, ip):
    rbytes = b'\xc0\x0c'

    rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes += int(ttl).to_bytes(4, byteorder='big')

    rbytes = rbytes + bytes([0]) + bytes([4])
    for part in ip.split('.'):
        rbytes += bytes([int(part)])

    return rbytes


def respond(data):
    tid_b = data[:2]

    flags = get_flags(data[2:4])
    qdc = b'\x00\x01'
    anc = (ip_amount_to_send if ip_amount_to_send <= len(ips) else len(ips)).to_bytes(2, byteorder='big')
    nsc = b'\x00\x00'
    arc = b'\x00\x00'

    header = tid_b + flags + qdc + anc + nsc + arc

    question = build_question()

    body = b''
    records = list(dict.fromkeys(random.choices(ips, k=ip_amount_to_send)))
    if len(ips) != 0:
        for record in records:
            body += rec_to_bytes(600, record)

    return header + question + body, records


def run_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip_extern, 53))
    while 1:
        sock.settimeout(None)
        data, (ip, port) = sock.recvfrom(512)
        r, recs = respond(data)
        with lock:
            global to_search
            to_search.append(ip)

        print('request from: ' + ip + ' on port ' + str(port) + ", response:", recs)

        sock.sendto(r, (ip, port))


# endregion


# region crawler

def run_crawler():
    pass
    # global ips, to_search, last_beat
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.bind((ip_extern, 10541))
    # sock.settimeout(5)
    # while 1:
    #     if not len(to_search) == 0:
    #         for ip in to_search:
    #             try:
    #                 sock.sendto(b'\x00\x01', (ip, 10541))
    #                 sock.recvfrom(256)
    #                 add_ip(ip)
    #                 print('valid node found at ' + ip)
    #             except socket.timeout:
    #                 pass
    #         to_search = []
    #
    #     if time.time() - last_beat >= 5:
    #         last_beat = time.time()
    #         for ip in ips:
    #             try:
    #                 sock.sendto(b'\x00\x01', (ip, 10541))
    #                 sock.recvfrom(256)
    #             except socket.timeout:
    #                 print('time out at ' + str(ip))
    #                 # remove_ip(ip)


# endregion

class Thread(threading.Thread):
    def __init__(self, t, *args):
        threading.Thread.__init__(self, target=t, args=args)
        self.start()


if __name__ == '__main__':
    load_ips()
    try:
        Thread(run_dns)
        Thread(run_crawler)
        while 1:
            inp = input()
            if inp == 'quit()' or inp == '^Z':
                sys.exit('bye')
            add_ip(inp)
    except KeyboardInterrupt:
        quit(0)
        sys.exit('bye')
