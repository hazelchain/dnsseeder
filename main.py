import random
import socket
import sys

if len(sys.argv) != 3:
    raise ValueError('unexpected input\nUsage: python <localIp> <ip expected>')

ip_extern = sys.argv[1]
expected_ip = sys.argv[2]
ips = [str]
ip_amount_to_send = 25


# region dns

def load_ips():
    global ips
    ips = []
    with open('ips', 'r') as file:
        for line in file.readlines():
            ips.append(line.removesuffix('\n'))

    print(ips)


def add_ip(ip):
    global ips
    with open('ips', 'a') as file:
        file.write('\n' + ip)
        ips += ip


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
    anc = ip_amount_to_send.to_bytes(2, byteorder='big')
    nsc = b'\x00\x00'
    arc = b'\x00\x00'

    header = tid_b + flags + qdc + anc + nsc + arc

    question = build_question()

    body = b''
    for record in list(dict.fromkeys(random.choices(ips, k=ip_amount_to_send))):
        body += rec_to_bytes(600, record)

    return header + question + body


# endregion


if __name__ == '__main__':
    load_ips()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip_extern, 53))
    while 1:
        data, addr = sock.recvfrom(512)
        r = respond(data)
        sock.sendto(r, addr)
