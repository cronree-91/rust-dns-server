import struct

def parse_dns_packet(data):
    header = struct.unpack('!HHHHHH', data[:12])
    _id = header[0]
    qr = (header[1] >> 15) & 0x1
    opcode = (header[1] >> 11) & 0xf
    aa = (header[1] >> 10) & 0x1
    tc = (header[1] >> 9) & 0x1
    rd = (header[1] >> 8) & 0x1
    ra = (header[1] >> 7) & 0x1
    z = (header[1] >> 4) & 0x7
    rcode = header[1] & 0xf
    qdcount = header[2]
    ancount = header[3]
    nscount = header[4]
    arcount = header[5]

    # 問い合わせセクションの解析
    question_start = 12
    question_end = question_start + qdcount * 12
    question_data = data[question_start:question_end]

    questions = []
    for i in range(qdcount):
        qname = ''
        qname_length = 0
        offset = question_start + qname_length
        while True:
            qname_length = struct.unpack('!B', data[offset:offset+1])[0]
            if qname_length == 0:
                break
            if len(qname) > 0:
                qname += '.'
            qname += data[offset+1:offset+1+qname_length].decode('utf-8')
            offset += qname_length + 1

        qtype, qclass = struct.unpack('!HH', data[offset+1:offset+5])
        questions.append((qname, qtype, qclass))

    return {
        'id': _id,
        'qr': qr,
        'opcode': opcode,
        'aa': aa,
        'tc': tc,
        'rd': rd,
        'ra': ra,
        'z': z,
        'rcode': rcode,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount,
        'questions': questions
    }

# 使用例
data = b"\x1bd\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x04test\x03com\x00\x00\x01\x00\x01\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\xd2\xad\x9f\xee\xbc=\xcc\xda"

parsed_packet = parse_dns_packet(data)

print(parsed_packet)