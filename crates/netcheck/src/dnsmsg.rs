//! Just enough DNS wire format for A lookups and mDNS answers.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Ptr(String),
    Srv { port: u16, target: String },
    Txt(Vec<String>),
    Other,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub data: RData,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u16,
    pub rcode: u8,
    pub answers: Vec<Record>,
    /// Answers, authority and additional records together.
    pub records: Vec<Record>,
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Builds a query. `class` may carry the mDNS "unicast response" bit (0x8001).
pub fn build_query(id: u16, questions: &[(&str, u16, u16)], recursion: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&(if recursion { 0x0100u16 } else { 0 }).to_be_bytes());
    b.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, t, c) in questions {
        for label in name.trim_end_matches('.').split('.') {
            let l = &label.as_bytes()[..label.len().min(63)];
            b.push(l.len() as u8);
            b.extend_from_slice(l);
        }
        b.push(0);
        b.extend_from_slice(&t.to_be_bytes());
        b.extend_from_slice(&c.to_be_bytes());
    }
    b
}

fn read_name(b: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = vec![];
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *b.get(off + 1)? as usize;
            if end.is_none() {
                end = Some(off + 2);
            }
            jumps += 1;
            if jumps > 20 {
                return None;
            }
            off = ptr;
            continue;
        }
        let s = b.get(off + 1..off + 1 + len)?;
        labels.push(String::from_utf8_lossy(s).to_string());
        off += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(off)))
}

pub fn parse(b: &[u8]) -> Option<Message> {
    if b.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([b[0], b[1]]);
    let rcode = b[3] & 0x0f;
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let counts = [u16::from_be_bytes([b[6], b[7]]), u16::from_be_bytes([b[8], b[9]]), u16::from_be_bytes([b[10], b[11]])];
    let mut off = 12;
    for _ in 0..qd {
        let (_, o) = read_name(b, off)?;
        off = o + 4;
    }
    let mut answers = vec![];
    let mut records = vec![];
    for (sec, n) in counts.iter().enumerate() {
        for _ in 0..*n {
            let (name, o) = read_name(b, off)?;
            off = o;
            let h = b.get(off..off + 10)?;
            let t = u16::from_be_bytes([h[0], h[1]]);
            let len = u16::from_be_bytes([h[8], h[9]]) as usize;
            off += 10;
            let rd = b.get(off..off + len)?;
            let data = match t {
                TYPE_A if len == 4 => RData::A(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])),
                TYPE_PTR => read_name(b, off).map(|(n, _)| RData::Ptr(n)).unwrap_or(RData::Other),
                TYPE_SRV if len >= 7 => {
                    let port = u16::from_be_bytes([rd[4], rd[5]]);
                    read_name(b, off + 6).map(|(n, _)| RData::Srv { port, target: n }).unwrap_or(RData::Other)
                }
                TYPE_TXT => {
                    let mut v = vec![];
                    let mut i = 0;
                    while i < rd.len() {
                        let l = rd[i] as usize;
                        if let Some(s) = rd.get(i + 1..i + 1 + l) {
                            v.push(String::from_utf8_lossy(s).to_string());
                        }
                        i += 1 + l;
                    }
                    RData::Txt(v)
                }
                _ => RData::Other,
            };
            off += len;
            let rec = Record { name, data };
            if sec == 0 {
                answers.push(rec.clone());
            }
            records.push(rec);
        }
    }
    Some(Message { id, rcode, answers, records })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_query_header() {
        let q = build_query(0x1234, &[("example.com", TYPE_A, 1)], true);
        let m = parse(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(m.answers.is_empty());
    }
    #[test]
    fn parses_compressed_answer() {
        // header: id 1, response, 1 question, 1 answer
        let mut b = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let m = parse(&b).unwrap();
        assert_eq!(m.answers[0].name, "example.com");
        assert!(matches!(m.answers[0].data, RData::A(a) if a == Ipv4Addr::new(93, 184, 216, 34)));
    }
}
