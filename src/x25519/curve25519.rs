#[allow(unused_imports)]
#[allow(unused_variables)]
#[allow(dead_code)]


const EVP_PKEY_X25519: i32 = 1034;
const EVP_PKEY_ED25519: i32 = 1087;

#[repr(C)]
struct ENGINE { _unused: [u8; 0] }
#[repr(C)]
struct EVP_MD { _unused: [u8; 0] }
#[repr(C)]
struct EVP_MD_CTX { _unused: [u8; 0] }
#[repr(C)]
struct EVP_PKEY_CTX { _unused: [u8; 0] }
#[repr(C)]
struct EVP_PKEY { _unused: [u8; 0] }

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SECRET_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = 64;

extern "C" {
    fn EVP_DigestSign(ctx: *mut EVP_MD_CTX, sigret: *mut ::std::os::raw::c_uchar, siglen: *mut usize, tbs: *const ::std::os::raw::c_uchar, tbslen: usize) -> ::std::os::raw::c_int;
    fn EVP_DigestSignInit(ctx: *mut EVP_MD_CTX, pctx: *mut *mut EVP_PKEY_CTX, type_: *const EVP_MD, e: *mut ENGINE, pkey: *mut EVP_PKEY) -> ::std::os::raw::c_int;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> ::std::os::raw::c_int;
    fn EVP_PKEY_derive_set_peer(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> ::std::os::raw::c_int;
    fn EVP_PKEY_derive(ctx: *mut EVP_PKEY_CTX, key: *mut ::std::os::raw::c_uchar, keylen: *mut usize) -> ::std::os::raw::c_int;
    fn EVP_PKEY_get_raw_private_key(pkey: *const EVP_PKEY, priv_: *mut ::std::os::raw::c_uchar, len: *mut usize) -> ::std::os::raw::c_int;
    fn EVP_PKEY_get_raw_public_key(pkey: *const EVP_PKEY, pub_: *mut ::std::os::raw::c_uchar, len: *mut usize) -> ::std::os::raw::c_int;
    fn EVP_PKEY_new_raw_private_key(type_: ::std::os::raw::c_int, e: *mut ENGINE, priv_: *const ::std::os::raw::c_uchar, len: usize) -> *mut EVP_PKEY;
    fn EVP_PKEY_new_raw_public_key(type_: ::std::os::raw::c_int, e: *mut ENGINE, pub_: *const ::std::os::raw::c_uchar, len: usize) -> *mut EVP_PKEY;
}

pub fn create_key_pair(secret: &[u8]) -> ([u8; PRIVATE_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
    let key = unsafe { EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, std::ptr::null_mut(), secret.as_ptr() as *mut u8, SECRET_KEY_SIZE) };

    let mut size = PRIVATE_KEY_SIZE;
    let mut private = [0u8; PRIVATE_KEY_SIZE];

    unsafe { EVP_PKEY_get_raw_private_key(key, private.as_mut_ptr(), &mut size); }
    assert_eq!(size, SECRET_KEY_SIZE);

    unsafe { EVP_PKEY_get_raw_public_key(key, private.as_mut_ptr().offset(SECRET_KEY_SIZE as isize), &mut size); }
    assert_eq!(size, PUBLIC_KEY_SIZE);

    let mut size = PUBLIC_KEY_SIZE;
    let mut public = [0u8; PUBLIC_KEY_SIZE];

    unsafe { EVP_PKEY_get_raw_public_key(key, public.as_mut_ptr(), &mut size); }
    assert_eq!(size, PUBLIC_KEY_SIZE);

    return (private, public);
}

pub fn calculate_public_key(secret: &[u8]) -> [u8; PUBLIC_KEY_SIZE] {
    let key = unsafe { EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, std::ptr::null_mut(), secret.as_ptr() as *mut u8, SECRET_KEY_SIZE) };

    let mut size = PUBLIC_KEY_SIZE;
    let mut public = [0u8; PUBLIC_KEY_SIZE];

    let status = unsafe { EVP_PKEY_get_raw_public_key(key, public.as_mut_ptr(), &mut size) };
    assert_eq!(status, 1);
    assert_eq!(size, PUBLIC_KEY_SIZE);

    public
}

pub fn create_shared_key(peer_public: &[u8], secret: &[u8]) -> [u8; SECRET_KEY_SIZE] {
    let key = unsafe { EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, std::ptr::null_mut(), secret.as_ptr() as *mut u8, SECRET_KEY_SIZE) };
    let peer_key = unsafe { EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, std::ptr::null_mut(), peer_public.as_ptr() as *mut u8, PUBLIC_KEY_SIZE) };

    let ctx = unsafe { EVP_PKEY_CTX_new(key, std::ptr::null_mut()) };

    let status = unsafe { EVP_PKEY_derive_init(ctx) };
    assert_eq!(status, 1);

    let status = unsafe { EVP_PKEY_derive_set_peer(ctx, peer_key) };
    assert_eq!(status, 1);

    let mut size = SECRET_KEY_SIZE;
    let mut result = [0u8; SECRET_KEY_SIZE];
    let status = unsafe { EVP_PKEY_derive(ctx, result.as_mut_ptr(), &mut size) };
    assert_eq!(status, 1);
    assert_eq!(size, SECRET_KEY_SIZE);

    result
}

pub fn sign_message(private_key: &[u8], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let ctx = unsafe { EVP_MD_CTX_new() };
    let key = unsafe { EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, std::ptr::null_mut(), private_key.as_ptr() as *mut u8, SECRET_KEY_SIZE) };

    let status = unsafe { EVP_DigestSignInit(ctx, std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), key) };
    assert_eq!(status, 1);

    let mut signature = [0u8; SIGNATURE_SIZE];
    let mut signature_length = SIGNATURE_SIZE;

    let status = unsafe { EVP_DigestSign(ctx, signature.as_mut_ptr(), &mut signature_length, message.as_ptr(), message.len()) };
    assert_eq!(status, 1);
    assert_eq!(signature_length, SIGNATURE_SIZE);

    signature
}