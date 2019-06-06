use libc;

const NUM_PRIMES: usize = 74;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CSIDHPrivateKey {
    e: [i8; NUM_PRIMES],
}

impl CSIDHPrivateKey {
    fn new() -> Self {
        CSIDHPrivateKey { e: [0i8; 74] }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CSIDHPublicKey {
    c: [u8; 64],
}

impl CSIDHPublicKey {
    fn new() -> Self {
        CSIDHPublicKey { c: [0u8; 64] }
    }
}

#[link(name = "csidh")]
extern "C" {
    pub fn csidh_generate(key: *mut CSIDHPrivateKey) -> libc::c_int;
    pub fn csidh_derive(out: *mut CSIDHPublicKey, base: *const CSIDHPublicKey, key: *const CSIDHPrivateKey) -> libc::c_int;
    pub static csidh_base: CSIDHPublicKey;
}

pub fn keypair() -> (CSIDHPublicKey, CSIDHPrivateKey) {
    let mut pk = CSIDHPublicKey::new();
    let mut sk = CSIDHPrivateKey::new();
    unsafe {
        csidh_generate(&mut sk as *mut CSIDHPrivateKey);
        csidh_derive(&mut pk as *mut CSIDHPublicKey,
                     &csidh_base as *const CSIDHPublicKey,
                     &sk as *const CSIDHPrivateKey);
    }

    (pk, sk)
}

pub fn agreement(theirs: &CSIDHPublicKey, ours: &CSIDHPrivateKey) -> [u8; 64] {
    let mut agreed = CSIDHPublicKey::new();
    unsafe {
        csidh_derive(&mut agreed as *mut CSIDHPublicKey,
                     theirs as *const CSIDHPublicKey,
                     ours as *const CSIDHPrivateKey);
    }
    agreed.c
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_agreement() {
        let (pka, ska) = keypair();
        let (pkb, skb) = keypair();

        let keya = agreement(&pka, &skb);
        let keyb = agreement(&pkb, &ska);

        assert_eq!(&keya[..], &keyb[..]);
    }
}
