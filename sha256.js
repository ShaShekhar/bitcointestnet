// OPERATION

function rotr(x, n, size=32) {
    // circular right shift, where x -> w-bit word and 0 <= n < w
    // in js >>> use to interpret result as a uinsigned no.
    return ((x >>> n) | (x << size-n) & (2**size-1)) >>> 0;
}

function shr(x, n) {
    // right shift operation, where x -> w-bit word and 0 <= n < w
    return x >>> n;
}

// SHA-256 use 6-logical function, where each function is operates on 32-bit words
// which are represented as x, y and z. Result is a new 32-bit word.

function ch(x, y, z) {
    // Choice function: uses input from x to take either value of y or z
    return ((x & y) ^ (~x & z)) >>> 0;
}

function maj(x, y, z) {
    // Majority function: result is the majority of three bits
    return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
}

function sig0(x) {
    return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)) >>> 0;
}

function sig1(x) {
    return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)) >>> 0;
}

function capsig0(x) {
    return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0;
}

function capsig1(x) {
    return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0;
}


function first_n_primes(n){
    const primeArr = []; // store prime no.
    let num = 2; // starting no.
    let isPrime = true; // assume every no. is prime
    for(let i = 0; i < n; num++){
        for(let j = 2; j*j <= num; j++){
            if(num % j === 0){
                isPrime = false; // divisible, not a prime
                break;
            }
        }
        if(!isPrime){
            isPrime = true; // reset the flag for next no.
        } else {
            primeArr.push(num);
            i++;
        }
    }
    return primeArr;
}

// return the first 32-bits of the fractinal part of float f.
function frac_bin(f){
    let f1 = f - Math.floor(f); // get only the fractional part
    f1 = f1 * 0x100000000; // multiply with 2**32
    f1 = parseInt(f1); // truncate the rest of the fractional part
    return f1;
}

// SHA-256 constants
// The first 32-bits of the fractional parts of the cube root of the first 64 prime numbers
function genK(){
    const shaK = new Uint32Array(64);
    const primes64 = first_n_primes(64);
    primes64.forEach(function(prime, index){
        shaK[index] = frac_bin(Math.pow(prime, 1/3));
    });
    return shaK;
}

// Initial Hash value
// The first 32-bits of the fractional parts of the square root of the first 8 prime numbers.
function genH(){
    const initialHash = new Uint32Array(8);
    const primes8 = first_n_primes(8);
    primes8.forEach(function(prime, index){
        initialHash[index] = frac_bin(Math.pow(prime, 1/2));
    });
    return initialHash;
}

// -----------------------------------------------------------------------------------------
// Preprocessing

// Convert hex String to a bitArray
function hexStringToArray_sha(hex_str){
    const out = []; // to store the 4 byte chunks of bitString
    const total_4b_chunk = parseInt(hex_str.length/8); // (len*4)/32 - 4 byte chunk
    const remaining_hex = hex_str.length % 8;

    for(let i = 0; i < total_4b_chunk; i++){
        out.push(parseInt(hex_str.substring(8*i, 8*i+8), 16));
    }
    if(remaining_hex){
        out.push(parseInt(hex_str.substring(8*total_4b_chunk), 16));
    }
    return out;
}

function pad_sha(hexString) {
    // console.log('in pad function');

    const msg_len = hexString.length*4; // message length in bits
    // (hexString.length/2) % 4 -> remaining chunk of 4 bytes
    const last_w_len = (hexString.length % 8)*4; // remaining bits.

    // console.log(`msg_len: ${msg_len}`);
    // console.log(`last_w_len: ${last_w_len}`);

    const data = hexStringToArray_sha(hexString);

    const uint32_data = new Uint32Array(data);
    // console.log(uint32_data);

    // PRE-PROCESSING
    // pad the message
    // append bit '1' to the end of the message
    // followed by k zero bits, where k is the smallest `non-negative` solution to 
    // l+1+k = 448 mod 512, i.e, pad with zeros until we reach 448 (mod 512)
    let last_byte, remaining_bytes = [];
    if(last_w_len === 0) {
        // for empty string, start with 1 and 31 0's.
        remaining_bytes.push((1 << 31) >>> 0);

    }else if(last_w_len === 8 || last_w_len === 16 || last_w_len === 24){
        // get the last byte
        last_byte = uint32_data[uint32_data.length-1]
        // append bit '1' to the end, while keeping the word size to be 32bits.
        last_byte = (last_byte << (32-last_w_len) | 1 << (32-last_w_len-1)) >>> 0;
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
        remaining_bytes.push(0);
        remaining_bytes.push(msg_len);
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

function sha256(hex_data) {
    // generate sha256 constants
    const K = genK();
    // console.log(`Constant: ${K}`);

    // Preprocessing: Pad the message
    // console.log('calling function pad.');
    const padded_msg = pad_sha(hex_data);
    // console.log(`padded_msg: ${padded_msg}`);

    const msg_len = padded_msg.length*32; // in bits
    const BLOCK_SIZE = 512;

    // generate sha256 initial Hash
    let Hash = genH();
    // console.log(`Hash: ${Hash}`);
    
    // declare some variables
    let W, delta;
    let term1,term2,term3,term4,total,
    a,b,c,d,e,f,g,h,T1,T2;

    let padded_hex, hash_output='';

    for(let i = 0; i < msg_len/BLOCK_SIZE; i++){
        // 1. Prepare the message schedule, a 64-entry array of 32-bit words
        W = new Uint32Array(64);
        for(let j = 0; j < 64; j++){
            if(j <= 15){
                // padded_msg.subarray(16*i, 16*(i+1))
                W[j] = padded_msg[16*i+j];
            } else {
                term1 = sig1(W[j-2]);
                term2 = W[j-7];
                term3 = sig0(W[j-15]);
                term4 = W[j-16];
                total = (term1 + term2 + term3 + term4) >>> 0;

                W[j] = total;
            }
        }
        // console.log(`W: ${W}`);
        // 2. Initialize the 8 working variable a,b,c,d,e,f,g,h with prev hash value
        [a, b, c, d, e, f, g, h] = Hash;

        // 3. iterate 64 times for message digest
        for(let j = 0; j < 64; j++){
            T1 = (h + capsig1(e) + ch(e, f, g) + K[j] + W[j]) >>> 0;
            T2 = (capsig0(a) + maj(a, b, c)) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + T1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) >>> 0;
        }
        // Computer the i-th intermedia hash value
        delta = [a, b, c, d, e, f, g, h];
        Hash.forEach(function(prev_hash, index){
            Hash[index] = (delta[index] + prev_hash) >>> 0;
        });
        // console.log(`Hash Output: ${Hash}`);
    }
    // return the hash in hex
    Hash.forEach(function(final_hash){
        padded_hex = (final_hash.toString(16)).padStart(8, '0');
        hash_output += padded_hex;
    });
    return hash_output;
}

// console.log(`verify empty hash: ${sha256('')}`);
