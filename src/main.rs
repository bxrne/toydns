mod bpb;
mod dns;

use std::error::Error;
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), Box<dyn Error>> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = bpb::BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let pck = dns::DNSPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", pck);

    for q in pck.questions {
        println!("Question: {:?}", q);
    }

    for a in pck.answers {
        println!("Answer: {:?}", a);
    }

    for rec in pck.authorities {
        println!("Authority: {:?}", rec);
    }

    for res in pck.resources {
        println!("Resource: {:?}", res);
    }

    Ok(())
}
