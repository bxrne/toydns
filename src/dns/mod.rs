mod header;
mod packet;
mod question;
mod record;

pub use header::{DNSHeader, ResultCode};
pub use packet::DNSPacket;
pub use question::{DNSQuestion, QueryType};
pub use record::DNSRecord;
