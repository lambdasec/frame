fn main() { let mut v: smallvec::SmallVec<[u8; 4]> = smallvec::SmallVec::new(); v.push(1); println!("{}", v.len()); }
