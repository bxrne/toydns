mod bpb;
mod dns;

use std::error::Error;
use std::net::UdpSocket;

use bpb::BytePacketBuffer;
use dns::{DNSPacket, DNSQuestion, QueryType};

fn main() -> Result<(), Box<dyn Error>> {
    // Perform an A query for google.com
    let qname = "www.yahoo.com";
    let qtype = QueryType::A;

    // Using google's public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DNSPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DNSQuestion::new(qname.to_string(), qtype));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DNSPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let res_packet = DNSPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
