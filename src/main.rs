use std::mem;
use byteorder::BigEndian;
use byteorder::ByteOrder;

#[repr(packed)]
#[derive(Debug)]
struct DnsHeader {
    arcount: u16,
    nscount: u16,
    ancount: u16,
    qdcount: u16,
    meta: u16,
    _id: u16,
}


fn parse_dns_header(array: &[u8]) {
    let mut sliced_array: [u8; 12] = [0,0,0,0,0,0,0,0,0,0,0,0];
    sliced_array.clone_from_slice(&array[..12]);

    sliced_array.reverse();

    let mut res;
    unsafe {
        res = mem::transmute::<[u8; 12], DnsHeader>(sliced_array);
    }

    println!("{:?}", res);
}

fn main() {
    let array = b"\x1bd\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x04test\x03com\x00\x00\x01\x00\x01\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\xd2\xad\x9f\xee\xbc=\xcc\xda";

    parse_dns_header(array);
}

