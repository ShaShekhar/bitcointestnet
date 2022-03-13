/*
Elliptic Curve Digital Signature Algorithm (ECDSA)
Functions that sign/verify digital signatures and related utilities
*/

class Signature {
    constructor(r, s){
        this.r = r; // bigint type
        this.s = s; // bitint type
    }
    
    decode(der_hex){
        /*
        DER has the following format.
        0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]
        total-length: 1-byte length descriptor of everything that follows, excluding the sighash byte.
        R-length: 1-byte length descriptor of the R value that follows.
        R: arbitrary-length big-endian encoded R value. It cannot start with any 0x00 bytes,
            unless the first byte that follows is 0x80 or higher, in which case a single 0x00 is required.
        S-length: 1-byte length descriptor of the S value that follows.
        S: arbitrary-length big-endian encoded S value. The rules apply as for R.

        sighash-type: 1-byte hashtype flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed)

        NOTE: the sighash type is just appended at the end of the DER signature at the end in
        Bitcoin transaction, and isn't actually part of the DER signature. Here we already assume it
        has been cropped out.
        */
       if(der_hex.substring(0, 2) !== '30'){
           throw new Error('der initial marker is not correct');
       } 
       // read and validate the total length of the encoding
       let length = der_hex.substring(2, 4);
       length = parseInt(length, 16);
       if(length !== der_hex.length-2){
           throw new Error('der length is not correct');
       }
       // validate r marker
       if(der_hex.substring(4, 6) !== '02'){
           throw new Error('der r marker is not correct');
        }
       // read r
       let rlength = der_hex.substring(6, 8);
       rlength = parseInt(rlength, 16);
       let rval = der_hex.substring(8, 8+rlength);
       rval = BigInt('0x' + rval);

       // validate s marker
       if(der_hex.substring(8+rlength, 8+rlength+2) !== '02'){
           throw new Error('der s marker is not correct');
        }
        // read s
        let slength = der_hex.substring(8+rlength+2, 8+rlength+2+2);
        slength = parseInt(slength, 16);
        let sval = der_hex.substring(8+rlength+2+2, 8+rlength+2+2+slength);
        rval = BigInt('0x' + sval);
        // validate total length and return
        if(der_hex.length !== 6+rlength+slength){
            throw new Error('der signature Length mismatch');
        }

        return Signature(rval, sval);
    }
    
    encode(){
        // return the DER encoding of this signature
        function der_sig(n){
            let nb = (n.toString(16)).padStart(64, '0');
            // strip leading zeros
            let counter = 0;
            while(true){
                if(nb.substring(2*counter, 2*counter+2) === '00'){
                    counter += 1;
                } else {
                    break;
                }
            }
            nb = nb.substring(counter);
            if(parseInt(nb.substring(0, 2), 16) >= 0x80){
                nb = '00' + nb;
            } 
            return nb;
        }
        const rb = der_sig(this.r);
        const sb = der_sig(this.s);
        const rb_content = '02' + parseInt(rb.length/2).toString(16).padStart(2, '0') + rb;
        const sb_content = '02' + parseInt(sb.length/2).toString(16).padStart(2, '0') + sb;
        const content_len = parseInt((rb_content.length+sb_content.length)/2); // byte length
        let frame = '30' + content_len.toString(16).padStart(2, '0');
        frame = frame + rb_content + sb_content;

        return frame;
    }
}

function sign(secret_key, message){
    // secp256k1 Generator point order
    // hash the message and convert to integer
    let z = sha256(sha256(message));
    z = BigInt('0x' + z); // convert to big endian integer

    // generate a new secret/public key pair at random
    // TODO: make deterministic -> use HMAC
    // TODO: make take constant time to mitigate timing attacks
    const sk = gen_secret_key(); // bigint, ephemeral key
    // console.log(sk);
    const pk = PublicKey.from_sk(sk);
    // calculate the signature
    const r = pk.x;
    let s = ((z + secret_key*r) * inverse(sk, ORD_G)) % ORD_G;
    if(s > ORD_G/2n){
        s = ORD_G - s;
    }
    return new Signature(r, s);
}

function verify(PUB_KEY, message, sig){
    // some basic verification
    if(typeof sig.r !== 'bigint' && sig.r > ORD_G && sig.r < 1){
        throw new Error('signature, r incorrect.');
    }
    if(typeof sig.s !== 'bigint' && sig.s > ORD_G && sig.s < 1){
        throw new Error('signature, s incorrect.');
    }
    // hash the message and convert to integer
    let z = sha256(sha256(message));
    z = BigInt('0x' + z); // convert to big endian integer

    // verify signature
    w = inverse(sig[1], ORD_G);
    const u1 = (z * w) % ORD_G;
    const u2 = (sig[0] * w) % ORD_G;

    const P = (G.multiply(u1)).add(PUB_KEY.multiply(u2));
    const match = P.x === sig.r;

    return match;
}