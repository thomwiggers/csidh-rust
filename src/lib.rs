use paste::paste;

macro_rules! ctidh_mod {
    ($size: literal, $num_primes: literal) => {paste!{
        pub mod [<ctidh $size>] {

            const NUM_PRIMES: usize = $num_primes;

            pub const PUBLIC_KEY_LEN: usize = 8 * (($size+63)/64);
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
                const fn new() -> Self {
                    CSIDHPrivateKey { e: [0i8; $num_primes] }
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
                c: [u8; PUBLIC_KEY_LEN],
            }

            impl std::ops::Deref for CSIDHPublicKey {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    unsafe { std::mem::transmute(&self.c[..]) }
                }
            }

            impl CSIDHPublicKey {
                const fn new() -> Self {
                    CSIDHPublicKey { c: [0u8; PUBLIC_KEY_LEN] }
                }

                pub fn from_private(private: &CSIDHPrivateKey) -> Self {
                    public_from_private(private)
                }

                pub const fn as_slice(&self) -> &[u8] {
                    &self.c
                }

                pub const fn as_bytes(&self) -> &[u8] {
                    self.as_slice()
                }

                pub fn from_bytes(bytes: &[u8]) -> Self {
                    let mut pk = Self::new();
                    pk.c.copy_from_slice(bytes);
                    pk
                }
            }

            #[link(name = "ctidh_" $size)]
            extern "C" {
                pub fn [< ctidh_rust_highctidh_ $size _csidh_private >](key: *mut CSIDHPrivateKey) -> libc::c_int;
                pub fn [< ctidh_rust_highctidh_ $size _csidh >](
                    out: *mut CSIDHPublicKey,
                    base: *const CSIDHPublicKey,
                    key: *const CSIDHPrivateKey,
                ) -> libc::c_int;
                pub static [< ctidh_rust_highctidh_ $size _base >]: CSIDHPublicKey;
            }

            pub fn generate_private() -> CSIDHPrivateKey {
                let mut sk = CSIDHPrivateKey::new();

                unsafe {
                    [< ctidh_rust_highctidh_ $size _csidh_private >](&mut sk as *mut CSIDHPrivateKey);
                }
                sk
            }

            pub fn public_from_private(key: &CSIDHPrivateKey) -> CSIDHPublicKey {
                let mut pk = CSIDHPublicKey::new();
                unsafe {
                    [< ctidh_rust_highctidh_ $size _csidh >](
                        &mut pk as *mut CSIDHPublicKey,
                        &[< ctidh_rust_highctidh_ $size _base >] as *const CSIDHPublicKey,
                        key as *const CSIDHPrivateKey,
                    );
                }
                pk
            }

            pub fn keypair() -> (CSIDHPublicKey, CSIDHPrivateKey) {
                let sk = generate_private();
                (public_from_private(&sk), sk)
            }

            pub fn agreement(theirs: &CSIDHPublicKey, ours: &CSIDHPrivateKey) -> [u8; PUBLIC_KEY_LEN] {
                let mut agreed = CSIDHPublicKey::new();
                unsafe {
                    [< ctidh_rust_highctidh_ $size _csidh >](
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
        }
    }}
}

ctidh_mod!(512, 74);
ctidh_mod!(1024, 130);