/*
Utilities to generate secret/public key pairs and Bitcoin address
(Note: using "secret" instead of "private" so that sk and pk are
easy consistent shortcuts of the two without collision)
*/

//---------------------------------------------------------------------------------
// Secret key generation. We're going to leave secret key as BigInt number type.
function gen_bigRandom_int(){
   const random_num = new Uint8Array(32);
   const rand_array = window.crypto.getRandomValues(random_num);
   let temp_str, bigInt_bin = '0b';

   rand_array.forEach(function(num){
        temp_str = num.toString(2).padStart(8, '0');
        bigInt_bin += temp_str;
   });
   const bigInt = BigInt(bigInt_bin);
    //console.log(`binInt: ${bigInt}`);
    return bigInt;
}

function gen_secret_key(){
    /*
    ORD_G is the upper bound on the key, typically the order of the elliptic curve we are using.
    The function will return a valid key, i.e. 1 <= key < n
    */
    let private_key;
    while(true){
        private_key = gen_bigRandom_int();
        if(private_key < ORD_G){
            break;
        }
    }
    return private_key;
}

class PublicKey extends Point {

    // method to return public key from secret key
    static from_sk(sk){
        // sk must be BigInt
        if(typeof sk !== 'bigint'){
            throw new Error('sk must be BigInt type');
        }
        const from_point = G.multiply(sk);

        return new PublicKey(from_point.x, from_point.y);
    }

    decode(pk_hex){
        // decode from the SEC binary format
        if(typeof pk_hex !== 'string'){
            throw new Error('Public Key must be hex string');
        }
        // the uncompressed version is straight forward
        if(pk_hex.substring(0, 2) === '04'){
            const x = BigInt('0x' + pk_hex.substring(2, 66));
            const y = BigInt('0x' + pk_hex.substring(66, 130));
            return new PublicKey(x, y);
        }
        // for compressed version uncompress the full public key Point
        const is_even = pk_hex.substring(0, 2) === '02';
        const x = BigInt('0x' + pk_hex.substring(2));
        // solve y^2 = x^3 + 7 mod p, for y
        const y2 = (((x*x) % this.p)*x + 7n) % this.p;
        let y = y2;
        for(let i = 1n; i < (this.p+1n)/4n; i++){
            y = (y*y2) % this.p;
        }
        if((y % 2n === 0n) === is_even){
            y = y;
        } else {
            y = this.p - y;
        }
        return new PublicKey(x, y);
    }

    encode(compressed, h160=true){
        // return the SEC bytes encoding of the public key Point
        // calculates the bytes
        let prefix, pk_bin, temp_x, temp_y;
        if(compressed){
            /*
            encode x, then y = +/-sqrt(x^3 + 7), so we need one more bit to encode whether it was
            + or - but because this is modular arithmetic there is no +/-, instead it can be shown
            that one y will always be even and other odd.
            */
            if(this.y % 2n === 0n){
                prefix = '02';
            } else {
                prefix = '03';
            }
            pk_bin = prefix + (this.x.toString(16)).padStart(64, '0'); // pad hex zero at the front
            // console.log(`prefix: ${prefix}`);
            // console.log(`prefix+x: ${pk_bin}`);
            // in sha256: generate chunk of 4 bytes - big-endian
        } else {
            prefix = '04';
            temp_x = (this.x.toString(16)).padStart(64, '0'); // pad hex zero at the front
    
            temp_y = (this.y.toString(16)).padStart(64, '0');
    
            pk_bin = prefix + temp_x + temp_y;
            // in sha256: generate chunk of 4 bytes
        }
        if(h160){
            const sha_output = sha256(pk_bin);
            // console.log(`sha256 output: ${sha_output}`);
            // convert sha_output to little endian
            const ripemd160_output = RIPEMD160(sha_output);
            // console.log(`ripemd160 output: ${ripemd160_output}`);
        
            return ripemd160_output;
        }
        return pk_bin;
    }
    
    bitcoin_address(net, compressed, h160){
        // return the associated bitcoin address for this public key string

        const pkb_hash = this.encode(compressed, h160);
        // add version byte (0x00 for Main Network, or 0x6f for Test Network)
        let version;
        if(net === 'main'){
            version = '00'; // 0x00
        } else if(net === 'test'){
            version = '6f'; // 0x6f
        }
        const ver_pkb_hash = version + pkb_hash;
        // console.log(`version pkb hash: ${ver_pkb_hash}`)
        // calculate the checksum
        const checksum = sha256(sha256(ver_pkb_hash));
        // console.log(`checksum: ${checksum}`);
        // append to form the full 25-byte binary Bitcoin Address
        const byte_address = ver_pkb_hash + checksum.substring(0, 8);
        // console.log(`address_checksum: ${byte_address}`);
        // finally b58 encode the result
        const b58check_address = b58encode(byte_address);

        return b58check_address;
    }

}
//---------------------------------------------------------------------------------------
// base58 encoding/decoding utilities
// reference: https://en.bitcoin.it/wiki/Base58Check_encoding

function b58encode(byte_address){
    let n = BigInt('0x' + byte_address); // big endian number
    const chars = [];
    let i;

    while(n){
        i = n % 58n;
        n = n / 58n;
        chars.push(ALPHABET[i]);
    }
    // special case handle the leading 0 bytes...
    let num_zeros = 0;
    while(true){
        if(byte_address.substring(2*num_zeros,2*num_zeros+2) === '00'){
            num_zeros += 1;
        } else {
            break;
        }
    }
    // prepend all the zeros that counter at the front, because otherwise
    // they wouldn't show up as prefixed ones.
    if(num_zeros === 0){
        return chars.reverse().join('');
    } else {
        const res = num_zeros * ALPHABET[0] + chars.reverse().join('');
        return res;
    }
}