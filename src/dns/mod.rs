mod header;
mod packet;
mod question;
mod record;

#[allow(unused_imports)]
pub use header::{DNSHeader, ResultCode};
pub use packet::DNSPacket;
pub use question::{DNSQuestion, QueryType};
#[allow(unused_imports)]
pub use record::DNSRecord;
