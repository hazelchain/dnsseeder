import glob
import json
import socket

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))


def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            name = data['$origin']
            jsonzone[name] = data

    return jsonzone


zonedata = load_zones()


def get_flags(flags):
    byte1 = bytes(flags[0:1])
    byte2 = bytes(flags[1:2])

    rflags = ''

    qr = '1'
    opcode = ''
    for bit in range(1, 5):
        opcode += str(ord(byte1) & (1 << bit))

    aa = '1'
    tc = '0'
    rd = '0'
    ra = '0'
    z = '000'
    rcode = '0000'

    return int(qr + opcode + aa + tc + rd, 2).to_bytes(1, byteorder='big') + int(ra + z + rcode, 2).to_bytes(1,
                                                                                                             byteorder='big')


def get_question_domain(data):
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0

            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte

        y += 1

    questiontype = data[y: y + 2]

    return domainparts, questiontype


def get_zone(domain):
    global zonedata

    zonename = '.'.join(domain)
    return zonedata[zonename]


def get_recs(data):
    domain, questiontype = get_question_domain(data)
    qt = ''

    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = get_zone(domain)

    return zone[qt], qt, domain


def build_question(domainname, rectype):
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')
    return qbytes


def rec_to_bytes(domainname, rectype, recttl, recval):
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])

    return rbytes


def build_response(data):
    transaction_id = data[:2]
    tid = ''
    for byte in transaction_id:
        tid += hex(byte)[2:]

    flags = get_flags(data[2:4])
    qdcount = b'\x00\x01'
    ancount = len(get_recs(data[12:])[0]).to_bytes(2, byteorder='big')
    nscount = (0).to_bytes(2, byteorder='big')
    arcount = (0).to_bytes(2, byteorder='big')
    dnsheader = transaction_id + flags + qdcount + ancount + nscount + arcount

    dnsbody = b''

    records, rectype, domainname = get_recs(data[12:])

    dnsquestion = build_question(domainname, rectype)

    for record in records:
        dnsbody += rec_to_bytes(domainname, rectype, record["ttl"], record["value"])

    print('header: ', len(dnsheader), '\t', ' '.join('{:02x}'.format(c) for c in dnsheader))
    print('question: ', len(dnsquestion), '\t', ' '.join('{:02x}'.format(c) for c in dnsquestion))
    print('answer: ', len(dnsbody), '\t', ' '.join('{:02x}'.format(c) for c in dnsbody))
    return dnsheader + dnsquestion + dnsbody


while 1:
    data, addr = sock.recvfrom(512)
    r = build_response(data)
    sock.sendto(r, addr)
