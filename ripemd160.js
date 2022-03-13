
// Initialize the constants
let K0 = 0x00000000,
    K1 = 0x5A827999,
    K2 = 0x6ED9EBA1,
    K3 = 0x8F1BBCDC,
    K4 = 0xA953FD4E;
let KK0 = 0x50A28BE6,
    KK1 = 0x5C4DD124,
    KK2 = 0x6D703EF3,
    KK3 = 0x7A6D76E9,
    KK4 = 0x00000000;

function ROL(x, n){
    return (((x << n) & 0xffffffff) | ((x >>> (32-n)))) >>> 0;
}

function F0(x, y, z){
    return (x ^ y ^ z) >>> 0;
}

function F1(x, y, z){
    return ((x & y) |(((~x) % 0x100000000) & z)) >>> 0;
}

function F2(x, y, z){
    return ((x | ((~y) % 0x100000000)) ^ z) >>> 0;
}

function F3(x, y, z){
    return (x & z) | (y & ((~z) % 0x100000000)) >>> 0;
}

function F4(x, y, z){
    return (x ^ (y | ((~z) % 0x100000000))) >>> 0;
}

function R(a, b, c, d, e, Fj, Kj, sj, rj, X){
    a = ((ROL((a + Fj(b, c, d) + X[rj] + Kj) % 0x100000000, sj) + e) % 0x100000000) >>> 0;
    c = ROL(c, 10);
    return [a, c];
}

// -----------------------------------------------------------------------------------------
// Preprocessing

function changeEndianness(string){
    const result = [];
    let len = parseInt(string.length/2); // string.length always be even.
    for(let i = 0; i < len; i++){
        result.unshift(string.substring(2*i, 2*i+2));
    }
    return result.join('');
}

// Convert hex String to a bitArray
function hexStringToArray_ripemd(hex_str){
    const out = []; // to store the 4 byte chunks of bitString
    const hex_length = parseInt(hex_str.length/8); // len*4/32 - 4 byte chunk
    const remaining_hex = hex_str.length % 8;
    let little_end;

    for(let i = 0; i < hex_length; i++){
        little_end = changeEndianness(hex_str.substring(8*i, 8*i+8))
        out.push(parseInt(little_end, 16));
    }
    if(remaining_hex){
        little_end = hex_str.substring(8*hex_length);
        out.push(parseInt(little_end, 16));
    }
    return out;
}

function pad_ripemd(hexString) {

    const msg_len = hexString.length*4; // message length in bits
    const last_w_len = (hexString.length % 8)*4;

    // console.log(`msg_len: ${msg_len}`);
    // console.log(`last_w_len: ${last_w_len}`);

    data = hexStringToArray_ripemd(hexString);

    const uint32_data = new Uint32Array(data);
    // console.log(`RIPEMD data: ${uint32_data}`);

    // PRE-PROCESSING
    // pad the message
    // append bit '1' to the end of the message
    // followed by k zero bits, where k is the smallest `non-negative` solution to 
    // l+1+k = 448 mod 512, i.e, pad with zeros until we reach 448 (mod 512)
    let last_byte, remaining_bytes = [];
    if(last_w_len === 0) {
        // for empty string, start with 1 and 31 0's.
        remaining_bytes.push((1 << 7) >>> 0);

    }else if(last_w_len === 8 || last_w_len === 16 || last_w_len === 24){
        // get the last byte
        last_byte = uint32_data[uint32_data.length-1]
        // append bit '1' to the end, while keeping the word size to be 32bits.
        last_byte = (last_byte | 1 << (last_w_len+7)) >>> 0;
        uint32_data.fill(last_byte, uint32_data.length-1);
    }
    
    while(true) {
        if((uint32_data.length*32 + remaining_bytes.length*32) % 512 === 448) {
            break;
        }
        remaining_bytes.push(0);    
    }
    // append the length byte
    if((uint32_data.length*32 + remaining_bytes.length*32) <= 2**32-1){
        remaining_bytes.push(msg_len); // little end first
        remaining_bytes.push(0);
    } else {
        throw new Error('Can only hash upto file size of 4GB.');
    }
    const uint32_padded_msg = new Uint32Array(uint32_data.length+remaining_bytes.length);

    uint32_data.forEach(function(num, index){
        uint32_padded_msg[index] = num;
    });
    remaining_bytes.forEach(function(num, index){
        uint32_padded_msg[index+uint32_data.length] = num;
    });

    return uint32_padded_msg;
}

function RIPEMD160Transform(state, M){

    let a, b, c, d, e;
    let aa, bb, cc, dd, ee;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    // Round 1
    [a, c] = R(a, b, c, d, e, F0, K0, 11,  0, M); // input: a b c d e -> a c
    [e, b] = R(e, a, b, c, d, F0, K0, 14,  1, M); // e a b c d -> e b
    [d, a] = R(d, e, a, b, c, F0, K0, 15,  2, M); // d e a b c -> d a
    [c, e] = R(c, d, e, a, b, F0, K0, 12,  3, M);
    [b, d] = R(b, c, d, e, a, F0, K0,  5,  4, M);
    [a, c] = R(a, b, c, d, e, F0, K0,  8,  5, M);
    [e, b] = R(e, a, b, c, d, F0, K0,  7,  6, M);
    [d, a] = R(d, e, a, b, c, F0, K0,  9,  7, M);
    [c, e] = R(c, d, e, a, b, F0, K0, 11,  8, M);
    [b, d] = R(b, c, d, e, a, F0, K0, 13,  9, M);
    [a, c] = R(a, b, c, d, e, F0, K0, 14, 10, M);
    [e, b] = R(e, a, b, c, d, F0, K0, 15, 11, M);
    [d, a] = R(d, e, a, b, c, F0, K0,  6, 12, M);
    [c, e] = R(c, d, e, a, b, F0, K0,  7, 13, M);
    [b, d] = R(b, c, d, e, a, F0, K0,  9, 14, M);
    [a, c] = R(a, b, c, d, e, F0, K0,  8, 15, M);  /* #15 */
    // Round 2
    [e, b] = R(e, a, b, c, d, F1, K1,  7,  7, M);
    [d, a] = R(d, e, a, b, c, F1, K1,  6,  4, M);
    [c, e] = R(c, d, e, a, b, F1, K1,  8, 13, M);
    [b, d] = R(b, c, d, e, a, F1, K1, 13,  1, M);
    [a, c] = R(a, b, c, d, e, F1, K1, 11, 10, M);
    [e, b] = R(e, a, b, c, d, F1, K1,  9,  6, M);
    [d, a] = R(d, e, a, b, c, F1, K1,  7, 15, M);
    [c, e] = R(c, d, e, a, b, F1, K1, 15,  3, M);
    [b, d] = R(b, c, d, e, a, F1, K1,  7, 12, M);
    [a, c] = R(a, b, c, d, e, F1, K1, 12,  0, M);
    [e, b] = R(e, a, b, c, d, F1, K1, 15,  9, M);
    [d, a] = R(d, e, a, b, c, F1, K1,  9,  5, M);
    [c, e] = R(c, d, e, a, b, F1, K1, 11,  2, M);
    [b, d] = R(b, c, d, e, a, F1, K1,  7, 14, M);
    [a, c] = R(a, b, c, d, e, F1, K1, 13, 11, M);
    [e, b] = R(e, a, b, c, d, F1, K1, 12,  8, M); /* #31 */
    // console.log(a, b, c, d, e);
    // Round 3
    [d, a] = R(d, e, a, b, c, F2, K2, 11,  3, M);
    [c, e] = R(c, d, e, a, b, F2, K2, 13, 10, M);
    [b, d] = R(b, c, d, e, a, F2, K2,  6, 14, M);
    [a, c] = R(a, b, c, d, e, F2, K2,  7,  4, M);
    [e, b] = R(e, a, b, c, d, F2, K2, 14,  9, M);
    [d, a] = R(d, e, a, b, c, F2, K2,  9, 15, M);
    [c, e] = R(c, d, e, a, b, F2, K2, 13,  8, M);
    [b, d] = R(b, c, d, e, a, F2, K2, 15,  1, M);
    [a, c] = R(a, b, c, d, e, F2, K2, 14,  2, M);
    [e, b] = R(e, a, b, c, d, F2, K2,  8,  7, M);
    [d, a] = R(d, e, a, b, c, F2, K2, 13,  0, M);
    [c, e] = R(c, d, e, a, b, F2, K2,  6,  6, M);
    [b, d] = R(b, c, d, e, a, F2, K2,  5, 13, M);
    [a, c] = R(a, b, c, d, e, F2, K2, 12, 11, M);
    [e, b] = R(e, a, b, c, d, F2, K2,  7,  5, M);
    [d, a] = R(d, e, a, b, c, F2, K2,  5, 12, M); /* #47 */
    // console.log(a, b, c, d, e);
    /* Round 4 */
    [c, e] = R(c, d, e, a, b, F3, K3, 11,  1, M);
    [b, d] = R(b, c, d, e, a, F3, K3, 12,  9, M);
    [a, c] = R(a, b, c, d, e, F3, K3, 14, 11, M);
    [e, b] = R(e, a, b, c, d, F3, K3, 15, 10, M);
    [d, a] = R(d, e, a, b, c, F3, K3, 14,  0, M);
    [c, e] = R(c, d, e, a, b, F3, K3, 15,  8, M);
    [b, d] = R(b, c, d, e, a, F3, K3,  9, 12, M);
    [a, c] = R(a, b, c, d, e, F3, K3,  8,  4, M);
    [e, b] = R(e, a, b, c, d, F3, K3,  9, 13, M);
    [d, a] = R(d, e, a, b, c, F3, K3, 14,  3, M);
    [c, e] = R(c, d, e, a, b, F3, K3,  5,  7, M);
    [b, d] = R(b, c, d, e, a, F3, K3,  6, 15, M);
    [a, c] = R(a, b, c, d, e, F3, K3,  8, 14, M);
    [e, b] = R(e, a, b, c, d, F3, K3,  6,  5, M);
    [d, a] = R(d, e, a, b, c, F3, K3,  5,  6, M);
    [c, e] = R(c, d, e, a, b, F3, K3, 12,  2, M); /* #63 */
    // console.log(a, b, c, d, e);
    /* Round 5 */
    [b, d] = R(b, c, d, e, a, F4, K4,  9,  4, M);
    [a, c] = R(a, b, c, d, e, F4, K4, 15,  0, M);
    [e, b] = R(e, a, b, c, d, F4, K4,  5,  5, M);
    [d, a] = R(d, e, a, b, c, F4, K4, 11,  9, M);
    [c, e] = R(c, d, e, a, b, F4, K4,  6,  7, M);
    [b, d] = R(b, c, d, e, a, F4, K4,  8, 12, M);
    [a, c] = R(a, b, c, d, e, F4, K4, 13,  2, M);
    [e, b] = R(e, a, b, c, d, F4, K4, 12, 10, M);
    [d, a] = R(d, e, a, b, c, F4, K4,  5, 14, M);
    [c, e] = R(c, d, e, a, b, F4, K4, 12,  1, M);
    [b, d] = R(b, c, d, e, a, F4, K4, 13,  3, M);
    [a, c] = R(a, b, c, d, e, F4, K4, 14,  8, M);
    [e, b] = R(e, a, b, c, d, F4, K4, 11, 11, M);
    [d, a] = R(d, e, a, b, c, F4, K4,  8,  6, M);
    [c, e] = R(c, d, e, a, b, F4, K4,  5, 15, M);
    [b, d] = R(b, c, d, e, a, F4, K4,  6, 13, M); /* #79 */
    // console.log(a, b, c, d, e);

    aa = a;
    bb = b;
    cc = c;
    dd = d;
    ee = e;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* Parallel round 1 */
    [a, c] = R(a, b, c, d, e, F4, KK0,  8,  5, M);
    [e, b] = R(e, a, b, c, d, F4, KK0,  9, 14, M);
    [d, a] = R(d, e, a, b, c, F4, KK0,  9,  7, M);
    [c, e] = R(c, d, e, a, b, F4, KK0, 11,  0, M);
    [b, d] = R(b, c, d, e, a, F4, KK0, 13,  9, M);
    [a, c] = R(a, b, c, d, e, F4, KK0, 15,  2, M);
    [e, b] = R(e, a, b, c, d, F4, KK0, 15, 11, M);
    [d, a] = R(d, e, a, b, c, F4, KK0,  5,  4, M);
    [c, e] = R(c, d, e, a, b, F4, KK0,  7, 13, M);
    [b, d] = R(b, c, d, e, a, F4, KK0,  7,  6, M);
    [a, c] = R(a, b, c, d, e, F4, KK0,  8, 15, M);
    [e, b] = R(e, a, b, c, d, F4, KK0, 11,  8, M);
    [d, a] = R(d, e, a, b, c, F4, KK0, 14,  1, M);
    [c, e] = R(c, d, e, a, b, F4, KK0, 14, 10, M);
    [b, d] = R(b, c, d, e, a, F4, KK0, 12,  3, M);
    [a, c] = R(a, b, c, d, e, F4, KK0,  6, 12, M); /* #15 */
    /* Parallel round 2 */
    [e, b] = R(e, a, b, c, d, F3, KK1,  9,  6, M);
    [d, a] = R(d, e, a, b, c, F3, KK1, 13, 11, M);
    [c, e] = R(c, d, e, a, b, F3, KK1, 15,  3, M);
    [b, d] = R(b, c, d, e, a, F3, KK1,  7,  7, M);
    [a, c] = R(a, b, c, d, e, F3, KK1, 12,  0, M);
    [e, b] = R(e, a, b, c, d, F3, KK1,  8, 13, M);
    [d, a] = R(d, e, a, b, c, F3, KK1,  9,  5, M);
    [c, e] = R(c, d, e, a, b, F3, KK1, 11, 10, M);
    [b, d] = R(b, c, d, e, a, F3, KK1,  7, 14, M);
    [a, c] = R(a, b, c, d, e, F3, KK1,  7, 15, M);
    [e, b] = R(e, a, b, c, d, F3, KK1, 12,  8, M);
    [d, a] = R(d, e, a, b, c, F3, KK1,  7, 12, M);
    [c, e] = R(c, d, e, a, b, F3, KK1,  6,  4, M);
    [b, d] = R(b, c, d, e, a, F3, KK1, 15,  9, M);
    [a, c] = R(a, b, c, d, e, F3, KK1, 13,  1, M);
    [e, b] = R(e, a, b, c, d, F3, KK1, 11,  2, M); /* #31 */
    // console.log(a, b, c, d, e);
    /* Parallel round 3 */
    [d, a] = R(d, e, a, b, c, F2, KK2,  9, 15, M);
    [c, e] = R(c, d, e, a, b, F2, KK2,  7,  5, M);
    [b, d] = R(b, c, d, e, a, F2, KK2, 15,  1, M);
    [a, c] = R(a, b, c, d, e, F2, KK2, 11,  3, M);
    [e, b] = R(e, a, b, c, d, F2, KK2,  8,  7, M);
    [d, a] = R(d, e, a, b, c, F2, KK2,  6, 14, M);
    [c, e] = R(c, d, e, a, b, F2, KK2,  6,  6, M);
    [b, d] = R(b, c, d, e, a, F2, KK2, 14,  9, M);
    [a, c] = R(a, b, c, d, e, F2, KK2, 12, 11, M);
    [e, b] = R(e, a, b, c, d, F2, KK2, 13,  8, M);
    [d, a] = R(d, e, a, b, c, F2, KK2,  5, 12, M);
    [c, e] = R(c, d, e, a, b, F2, KK2, 14,  2, M);
    [b, d] = R(b, c, d, e, a, F2, KK2, 13, 10, M);
    [a, c] = R(a, b, c, d, e, F2, KK2, 13,  0, M);
    [e, b] = R(e, a, b, c, d, F2, KK2,  7,  4, M);
    [d, a] = R(d, e, a, b, c, F2, KK2,  5, 13, M); /* #47 */
    // console.log(a, b, c, d, e);
    /* Parallel round 4 */
    [c, e] = R(c, d, e, a, b, F1, KK3, 15,  8, M);
    [b, d] = R(b, c, d, e, a, F1, KK3,  5,  6, M);
    [a, c] = R(a, b, c, d, e, F1, KK3,  8,  4, M);
    [e, b] = R(e, a, b, c, d, F1, KK3, 11,  1, M);
    [d, a] = R(d, e, a, b, c, F1, KK3, 14,  3, M);
    [c, e] = R(c, d, e, a, b, F1, KK3, 14, 11, M);
    [b, d] = R(b, c, d, e, a, F1, KK3,  6, 15, M);
    [a, c] = R(a, b, c, d, e, F1, KK3, 14,  0, M);
    [e, b] = R(e, a, b, c, d, F1, KK3,  6,  5, M);
    [d, a] = R(d, e, a, b, c, F1, KK3,  9, 12, M);
    [c, e] = R(c, d, e, a, b, F1, KK3, 12,  2, M);
    [b, d] = R(b, c, d, e, a, F1, KK3,  9, 13, M);
    [a, c] = R(a, b, c, d, e, F1, KK3, 12,  9, M);
    [e, b] = R(e, a, b, c, d, F1, KK3,  5,  7, M);
    [d, a] = R(d, e, a, b, c, F1, KK3, 15, 10, M);
    [c, e] = R(c, d, e, a, b, F1, KK3,  8, 14, M); /* #63 */
    // console.log(a, b, c, d, e);
    /* Parallel round 5 */
    [b, d] = R(b, c, d, e, a, F0, KK4,  8, 12, M);
    [a, c] = R(a, b, c, d, e, F0, KK4,  5, 15, M);
    [e, b] = R(e, a, b, c, d, F0, KK4, 12, 10, M);
    [d, a] = R(d, e, a, b, c, F0, KK4,  9,  4, M);
    [c, e] = R(c, d, e, a, b, F0, KK4, 12,  1, M);
    [b, d] = R(b, c, d, e, a, F0, KK4,  5,  5, M);
    [a, c] = R(a, b, c, d, e, F0, KK4, 14,  8, M);
    [e, b] = R(e, a, b, c, d, F0, KK4,  6,  7, M);
    [d, a] = R(d, e, a, b, c, F0, KK4,  8,  6, M);
    [c, e] = R(c, d, e, a, b, F0, KK4, 13,  2, M);
    [b, d] = R(b, c, d, e, a, F0, KK4,  6, 13, M);
    [a, c] = R(a, b, c, d, e, F0, KK4,  5, 14, M);
    [e, b] = R(e, a, b, c, d, F0, KK4, 15,  0, M);
    [d, a] = R(d, e, a, b, c, F0, KK4, 13,  3, M);
    [c, e] = R(c, d, e, a, b, F0, KK4, 11,  9, M);
    [b, d] = R(b, c, d, e, a, F0, KK4, 11, 11, M); /* #79 */
    // console.log(a, b, c, d, e);

    t = (state[1] + cc + d) % 0x100000000;
    state[1] = (state[2] + dd + e) % 0x100000000;
    state[2] = (state[3] + ee + a) % 0x100000000;
    state[3] = (state[4] + aa + b) % 0x100000000;
    state[4] = (state[0] + bb + c) % 0x100000000;
    state[0] = t;
    // console.log(state);
    return state;
}

function RIPEMD160(data){
    // Initialize the MD buffers
    let state = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    // Preprocessing: Pad the message
    const padded_msg = pad_ripemd(data);
    // console.log(`ripemd padded msg: ${padded_msg}`);

    const msg_len = padded_msg.length*32; // in bits
    const BLOCK_SIZE = 512;

    let hash_output = '';
    let W, padded_hex;

    for(let i = 0; i < msg_len/BLOCK_SIZE; i++){
        // Prepare the message: a 16-entry array of 32-bit words
        W = new Uint32Array(16);
        for(let j = 0; j < 16; j++){
            W[j] = padded_msg[16*i+j];
        }
        state = RIPEMD160Transform(state, W);
    }
    // console.log(state);
    // return the hash in hex
    state.forEach(function(final_hash){
        padded_hex = (final_hash.toString(16)).padStart(8, '0');
        hash_output += changeEndianness(padded_hex);
    });
    return hash_output
}

// console.log(RIPEMD160('9f098bd85b052906999cae7459ef374d752eb7b53d4592d7d3cc6c193bb062ed'));