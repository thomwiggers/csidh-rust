use libc;

const NUM_PRIMES: usize = 74;

#[repr(C)]
pub struct CSIDHPrivateKey {
    _e: [i8; NUM_PRIMES],
}

#[repr(C)]
pub struct CSIDHPublicKey {
    _c: [u8; 64],
}

#[link(name = "csidh")]
extern "C" {
    pub fn csidh_generate(key: *mut CSIDHPrivateKey) -> libc::c_int;
    pub fn csidh_derive(out: *mut CSIDHPublicKey, base: *const CSIDHPublicKey, key: *const CSIDHPrivateKey) -> libc::c_int;
    pub static CSIDH_BASE: CSIDHPublicKey;
}
