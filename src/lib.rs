use libc;

const NUM_PRIMES: usize = 74;

pub const PUBLIC_KEY_LEN: usize = 64;
pub const PRIVATE_KEY_LEN: usize = NUM_PRIMES;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CSIDHPrivateKey {
    e: [i8; NUM_PRIMES],
}

impl std::ops::Deref for CSIDHPrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute(&self.e[..]) }
    }
}

pub type PublicKey = CSIDHPublicKey;
pub type SecretKey = CSIDHPrivateKey;

impl CSIDHPrivateKey {
    fn new() -> Self {
        CSIDHPrivateKey { e: [0i8; 74] }
    }

    pub fn generate() -> Self {
        generate_private()
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { &*((&self.e[..]) as *const _ as *const [u8]) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let i8bytes: &[i8] = unsafe { &*(bytes as *const _ as *const [i8]) };
        let mut sk = CSIDHPrivateKey::new();
        sk.e.copy_from_slice(i8bytes);
        sk
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CSIDHPublicKey {
    c: [u8; 64],
}

impl std::ops::Deref for CSIDHPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute(&self.c[..]) }
    }
}

impl CSIDHPublicKey {
    fn new() -> Self {
        CSIDHPublicKey { c: [0u8; 64] }
    }

    pub fn from_private(private: &CSIDHPrivateKey) -> Self {
        public_from_private(private)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.c
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut pk = Self::new();
        pk.c.copy_from_slice(bytes);
        pk
    }
}

#[link(name = "csidh")]
extern "C" {
    pub fn csidh_generate(key: *mut CSIDHPrivateKey) -> libc::c_int;
    pub fn csidh_derive(
        out: *mut CSIDHPublicKey,
        base: *const CSIDHPublicKey,
        key: *const CSIDHPrivateKey,
    ) -> libc::c_int;
    pub static csidh_base: CSIDHPublicKey;
}

pub fn generate_private() -> CSIDHPrivateKey {
    let mut sk = CSIDHPrivateKey::new();

    unsafe {
        csidh_generate(&mut sk as *mut CSIDHPrivateKey);
    }
    sk
}

pub fn public_from_private(key: &CSIDHPrivateKey) -> CSIDHPublicKey {
    let mut pk = CSIDHPublicKey::new();
    unsafe {
        csidh_derive(
            &mut pk as *mut CSIDHPublicKey,
            &csidh_base as *const CSIDHPublicKey,
            key as *const CSIDHPrivateKey,
        );
    }
    pk
}

pub fn keypair() -> (CSIDHPublicKey, CSIDHPrivateKey) {
    let sk = generate_private();
    (public_from_private(&sk), sk)
}

pub fn agreement(theirs: &CSIDHPublicKey, ours: &CSIDHPrivateKey) -> [u8; 64] {
    let mut agreed = CSIDHPublicKey::new();
    unsafe {
        csidh_derive(
            &mut agreed as *mut CSIDHPublicKey,
            theirs as *const CSIDHPublicKey,
            ours as *const CSIDHPrivateKey,
        );
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
