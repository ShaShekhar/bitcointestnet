/*
The Transaction object in Bitcoin.
Reference: https://en.bitcoin.it/wiki/Transaction
*/

// helper function
function little_endian_to_int(hex_str, nbytes){
    // first convert from little endian to big endian
    if(nbytes > 1){
        const result = [];
        for(let i = 0; i < hex_str.length/2; i++){
            result.unshift(hex_str.substring(2*i, 2*i+2));
        }
        return parseInt(result.join(''), 16);
    }
    // else return the number
    return parseInt(hex_str, 16);
}

function int_to_little_endian(int, nbytes){
    const data_hex = (int.toString(16)).padStart(nbytes*2, '0');
    if(nbytes > 1){
        const result = [];
        for(let i = 0; i < data_hex.length/2; i++){
            result.unshift(data_hex.substring(2*i, 2*i+2));
        }
        return result.join('');
    }
    // else return the data_hex
    return data_hex;
}

function big_to_little_endian(hex){
    const result = [];
    for(let i = 0; i < hex.length/2; i++){
        result.unshift(hex.substring(2*i, 2*i+2));
    }
    return result.join('');
}

function little_to_big_endian(hex){
    const result = [];
    for(let i = 0; i < hex.length/2; i++){
        result.unshift(hex.substring(2*i, 2*i+2));
    }
    return result.join('');
}

function encode_varint(i){
    // encodes an integer as a varint
    if(i < 0xfd){
        // below 253, encode as a single byte
        return int_to_little_endian(i, 1);
    } else if(i < 0x10000){
        // between 253 and 2**16-1, encode in 2 bytes in little-endian
        return 'fd' + int_to_little_endian(i, 2);
    } else if(i < 0x100000000){
        // between 2**16 and 2**32-1, encode in 4 bytes in LE
        return 'fe' + int_to_little_endian(i, 4);
    } else if(i < 0x10000000000000000){
        // between 2**32 and 2**64-1, encode in 8 bytes in LE
        return 'ff' + int_to_little_endian(i, 8);
    } else {
        throw new Error(`integer too large: ${i}`);
    }
}

function decode_varint(s){
    // console.log('decoding varint');
    // reads a variable integer from a byte object
    const i = little_endian_to_int(s.substring(0, 2), 1);
    // console.log(`const i: ${i}`);
    if(i === 0xfd){
        // 0xfd means next two bytes are the number
        return [little_endian_to_int(s.substring(2, 6), 2), s.substring(6)];
    } else if(i === 0xfe){
        // 0xfe means the next four bytes are the number
        return [little_endian_to_int(s.substring(2, 10), 4), s.substring(10)];
    } else if(i === 0xff){
        // 0xff means the next eight bytes are the number
        return [little_endian_to_int(s.substring(2, 18), 8), s.substring(18)];
    } else {
        return [i, s.substring(2)];
    }
}

// fetches transaction using an api on demand
class TxFetcher {

    static fetch(Txid, net){
        console.log('TxFetcher called...');
        const tx_id = Txid.toLowerCase(); // normalize just in case we get caps
        // fetch bytes from api
        // console.log(`fetching transaction ${tx_id} from API`);
        let url;
        if(net === 'main'){
            url = `https://blockstream.info/api/tx/${tx_id}/hex`;
        } else if(net === 'test'){
            url = `https://blockstream.info/testnet/api/tx/${tx_id}/hex`;
        } else {
            throw new Error(`${net} is not valid net type, should be main|test`);
        }
        let tx_output; // error_flag = false;

        var requestOptions = {method: 'GET', redirect: 'follow'};
        fetch(url, requestOptions)
            .then(function(response){
                if(!response.ok){
                    throw new Error(response.statusText);
                }
                return response.text();
            })
            .then(function(result){
                tx_output = result;
                // console.log(`tx_output: ${tx_output}`);
                // throw new Error('abort!!!');
                const tx = Tx.decode(tx_output);
                // ensure that the calculated id matches the request id
                if(tx.id() !== tx_id){
                    console.log('Invalid transaction.');
                }
                return tx;
            })
            .catch(function(error){
                console.log('transaction id was not found on blockchain.');
                console.log(error);
            });
    }
}

// TxIn class
class TxIn {
    constructor(prev_tx_id, tx_index, script_sig, sequence=0xffffffff){
        // hash256 of prev tx contents
        this.prev_tx_id = prev_tx_id; // big-endian hex
        this.tx_index = tx_index; // UTXO output index in the transaction
        this.script_sig = script_sig; // unlocking script
        this.sequence = sequence; //0xffffffff
        this.witness = null;
        this.net = 'test'; // which net are we on? eg 'main'|'test'
    }
    static decode(s, segwit_flag){
        const prev_tx_id = little_to_big_endian(s.substring(0, 64)); // 32 bytes little endian
        const tx_index = little_endian_to_int(s.substring(64, 72), 4);
        // decode varint
        // if(segwit_flag){}
        let [length, str] = decode_varint(s.substring(36));
        const script_sig = Script.decode(str.substring(0, length));
        const sequence = little_endian_to_int(str.substring(length, length+8), 4);

        return {
            TxIn_Obj: new TxIn(prev_tx_id, tx_index, script_sig),
            remaining_str: str.substring(length+8),
        }
    }

    encode(script_override){
        // console.log('TxIn encoding...');
        const out = [];
        out.push(big_to_little_endian(this.prev_tx_id)); // 32 bytes little endian
        out.push(int_to_little_endian(this.tx_index, 4));

        if(script_override === null){
            // just use the actual script
            out.push(this.script_sig.encode());
        } else if(script_override === true){
            // override the script with the script_pubkey of the associcated input
            // const tx = TxFetcher.fetch(this.prev_tx_id, this.net);
            // out.push(tx.tx_outs[this.tx_index].script_pubkey.encode());
            out.push(this.script_sig.encode());
            // console.log('using prefixed value, Not Fetching');
        } else if(script_override === false){
            // override with an empty script
            out.push(new Script([]).encode());
        } else {
            throw new Error("script_override must be one of null|true|false");
        }

        out.push(int_to_little_endian(this.sequence, 4));
        // console.log(`TxIn encoding: ${out}`);

        return out.join('');
    }

    get_value(){
        // look the amount up on the previous transaction
        const tx = TxFetcher.fetch(this.prev_tx_id, net=this.net);
        const amount = tx.tx_outs[this.prev_tx_id].amount;
        return amount;
    }

    script_pubkey(){
        // look the script_pubkey up on the previous transaction
        const tx = TxFetcher.fetch(this.prev_tx_id, net=this.net);
        const script = tx.tx_outs[this.tx_index].script_pubkey;
        return script;
    }
}

class TxOut {
    constructor(amount, script_pubkey){
        this.amount = amount; // in units of satoshi
        this.script_pubkey = script_pubkey; // locking script
    }
    static decode(s){
        const amount = little_endian_to_int(s.substring(0, 16), 8);
        const script_pubkey = Script.decode(s.substring(8));

        return {
            TxOut_Obj: new TxOut(amount, script_pubkey.script_obj),
            remaining_str: script_pubkey.remaining_str,
        }
    }
    encode(){
        // console.log('TxOut encoding...');
        const out = [];
        out.push(int_to_little_endian(this.amount, 8));
        out.push(this.script_pubkey.encode());
        // console.log(`TxOut encoding: ${out}`);

        return out.join('');
    }
}

class Tx {
    constructor(version, tx_ins, tx_outs, locktime, segwit){
        this.version = version; // int
        this.tx_ins = tx_ins; // array: [txins1, txins2...]
        this.tx_outs = tx_outs; // array: [txout1, txout2...]
        this.locktime = locktime; // int
        this.segwit = segwit; // bool: true|false
    }

    static decode(hex_str){
        console.log('decoding fetched Tx');
        // s is a stream of bytes in hex
        // decode version
        const version = little_endian_to_int(hex_str.substring(0, 8), 4);
        console.log(`version: ${version}`);
        // decode inputs + detect segwit transactions
        let num_inputs, s, segwit = false;
        if(hex_str.substring(8, 10) === '00'){ // check for segwit marker '00'
            if(hex_str.substring(10, 12) === '01'){
                [num_inputs, s] = decode_varint(hex_str.substring(12)); // override num_inputs
                segwit = true;
                console.log(`s: ${s}`);
            }
        } else {
            [num_inputs, s] = decode_varint(hex_str.substring(8)); // override num_inputs
        }

        const inputs = [];
        let TxIns;
        for(let i = 0; i < num_inputs; i++){
            TxIns = TxIn.decode(s, this.segwit);
            inputs.push(TxIns.TxIn_Obj);
            s = TxIns.remaining_str;
        }
        // decode outputs
        [num_outputs, s] = decode_varint(s);
        const outputs = [];
        let TxOuts;
        for(let i = 0; i < num_outputs; i++){
            TxOuts = TxOut.decode(s);
            outputs.push(TxOuts.TxOut_Obj);
            s = TxOuts.remaining_str;
        }
        // decode witness in the case of segwit
        if(segwit){
            let num_items, items, item_len;
            for(let i = 0; i < inputs.length; i++){
                [num_items, s] = decode_varint(s);
                items = [];
                for(let i = 0; i < num_items; i++){
                    [item_len, s] = decode_varint(s);
                    if(item_len === 0){
                        items.push(0);
                    } else {
                        items.push(s.substring(0, item_len));
                    }
                }
                inputs[i].witness = items;
            }
        }
        // decode locktime
        const locktime = little_endian_to_int(s, 4);

        return new Tx(version, inputs, outputs, locktime, segwit);
    }

    encode(force_legacy, sig_index=-1){
        /*
        serialize this transaction as hex string
        If sig_index is given then return the modified transaction encoding of
        this tx w.r.t the single input index. This result then constitutes the
        "message" that gets signed by the aspiring transactor of this input.
        */
        //console.log('Tx encoding...');
       const out = [];
       // encode metadata
       out.push(int_to_little_endian(this.version, 4));
       if(this.segwit && (!force_legacy)){
           out.push('0001'); // segwit marker + flag bytes
       }
       // encode inputs
       out.push(encode_varint(this.tx_ins.length));
        //console.log(`out: ${out}`);
       if(sig_index === -1){
           this.tx_ins.forEach(function(tx_in){
               out.push(tx_in.encode(true));
           });
       } else {
           this.tx_ins.forEach(function(tx_in, index){
               if(sig_index === index){
                   out.push(tx_in.encode(true));
               } else {
                   out.push(tx_in.encode(false));
               }
           });
       }
        //console.log(`out: ${out}`);
       // encode outputs
       out.push(encode_varint(self.tx_outs.length));
       this.tx_outs.forEach(function(tx_out){
            out.push(tx_out.encode());
        });
        // console.log(`out: ${out}`);
        // encode witness
        if(this.segwit && (!force_legacy)){
            this.tx_ins.forEach(function(tx_in){
                out.push(encode_varint(tx_in.witness.length));
                tx_in.witness.forEach(function(item){
                    if(typeof item === 'number'){
                        out.push(encode_varint(item));
                    } else {
                        out.push(encode_varint(item.length));
                        out.push(item);
                    }
                });
            });
        }
        // encode ... other metadata
        out.push(int_to_little_endian(this.locktime, 4));
        // console.log(`out: ${out}`);
        if(sig_index !== -1){
            out.push(int_to_little_endian(1, 4)); // 1 = SIGHASH_ALL
            // console.log(`out: ${out}`);
        }
        return out.join('');
    }
    id(){
        const force_legacy = true;
        const tx_id = sha256(sha256(this.encode(force_legacy, -1)));
        return big_to_little_endian(tx_id);
    }
    fee(){
        let input_total = 0, output_total = 0;
        this.tx_ins.forEach(function(tx_in){
            input_total += tx_in.get_value();
        });
        this.tx_outs.forEach(function(tx_out){
            output_total += tx_out.amount
        });

        return input_total-output_total;
    }

    validate(){
        // if segwit false then processed
        if(this.segwit){
            console.log('can not validate the segwit transaction.')
        }
        // validate that this transaction is not minting coins
        if(this.fee() < 0){
            return false;
        }
        // validate the digital signatures of all inputs
        let mod_tx_enc, combined, valid;
        this.tx_ins.forEach(function(tx_in, index){
            mod_tx_enc = this.encode(false, index);
            combined = tx_in.script_sig.concate(tx_in.script_pubkey());
            valid = combined.evaluate(mod_tx_enc);
            if(!valid){
                return false;
            }
        });
        return true;
    }

    is_coinbase(){
        const cb_tx = this.tx_ins[0];
        const cb_txid = '0000000000000000';
        if((this.tx_ins.length === 1) && (cb_tx.prev_tx_id === cb_txid) && (cb_tx.tx_index === 0xffffffff)){
            return true;
        } else {
            return false;
        }
    }

    coinbase_height(){
        // returns the block number of a given transaction, following BIP0034
        if(this.is_coinbase()){
            return int_from_little(this.tx_ins[0].script_sig.cmds[0])
        } else {
            return null;
        }
    }
}

class Script {
    constructor(cmds){
        this.cmds = cmds;
    }

    static decode(hex_stream){
        let [length,  s] = decode_varint(hex_stream); // length represent the no. of element
        const cmds = [];
        let count = 0; // number of bytes read
        let current, current_byte, data_length, op_code;

        while(count < length){
            current = s.substring(0, 2);
            count += 1;
            current_byte = parseInt(current); // read the current 1 byte as integer
            // push commands onto stack, elements as hex_string or ops as integer
            if(current_byte >= 1 && current_byte <= 75){
                // elements of size [1, 75] bytes
                cmds.push(s.substring(2, current_byte*2)); // read twice hex code
                count += current_byte;
                s = s.slice(2+current_byte*2);
            } else if(current_byte === 76){
                // OP_PUSHDATA1: elements of size [76, 255] bytes
                data_length = little_endian_to_int(s.substring(2, 4), 1);
                cmds.push(s.substring(4, data_length*2));
                count += data_length + 1;
                s = s.slice(4+data_length*2);
            } else if(current_byte === 77){
                // OP_PUSHDATA2: elements of size [256-520] bytes
                data_length = little_endian_to_int(s.substring(2, 6), 2);
                cmds.push(s.substring(6, data_length*2));
                count += data_length + 2;
                s = s.slice(6+data_length*2);
            } else {
                // represent an op_code, add it (as int)
                op_code = current_byte;
                cmds.push(op_code);
                s = s.slice(2);
            }
        }
        if(count !== length){
            throw new Error('parsing script failed');
        }

        return {
            script_obj: new Script(cmds),
            remaining_str: s,
        }
    }

    encode(){
        // console.log('Script encoding...');
        let length, result = '';
        // console.log(`full cmds: ${this.cmds}`);
        this.cmds.forEach(function(cmd){
            if(typeof cmd === 'number'){
                // an int is just an opcode, encode as a single byte
                result += int_to_little_endian(cmd, 1);
                // console.log(`Opcode encoding: ${int_to_little_endian(cmd, 1)}`);
            } else {
                // bytes represent an element, encode its length and then content
                length = parseInt(cmd.length/2); // in bytes
                if(length < 75){
                    result += int_to_little_endian(length, 1);
                    // console.log(`Bytes encoding: ${int_to_little_endian(length, 1)}`);
                } else if((length >= 76) && (length <= 255)){
                    // OP_PUSHDATA1
                    result += int_to_little_endian(76, 1);
                    result += int_to_little_endian(length, 1);
                    // console.log(`Bytes encoding: ${int_to_little_endian(76, 1)}`);
                    // console.log(`Bytes encoding: ${int_to_little_endian(length, 1)}`);
                } else if((length >= 256) && (length <= 520)){
                    // OP_PUSHDATA2
                    result += int_to_little_endian(77, 1);
                    result += int_to_little_endian(length, 2);
                    // console.log(`Bytes encoding: ${int_to_little_endian(77, 1)}`);
                    // console.log(`Bytes encoding: ${int_to_little_endian(length, 2)}`);
                } else {
                    throw new Error(`cmd of length ${length} bytes is too long?`);
                }
                result += cmd;
                // console.log(`cmd: ${cmd}`);
            }
        });
        const total_len = encode_varint(parseInt(result.length/2));
        // console.log(`varint encoding: ${total_len}`);
        return total_len + result;
    }

    evaluate(mod_tx_enc){
        // for now let's just support a standard p2pkh transaction
        if(this.cmds.length !== 7){
            return false;
        }
        // verify the public key hash, answering the OP_EQUALVERIFY challenge
        const pubkey = this.cmds[1];
        const pubkey_hash = this.cmds[4];
        const cal_pubkey_hash = RIPEMD160(sha256(pubkey));
        if(pubkey_hash !== cal_pubkey_hash){
            return false;
        }
        // verify the digital signature of the transaction, answering the OP_CHECKSIG challenge
        const sighash_type = this.cmds[0].substring(-1);
        if(sighash_type !== 1){
            return false;
        }
        const der = this.cmds[0].substring(0, -1); // DER encoded signature, but crop out the last byte
        const sec = this.cmds[1]; // SEC encoded public key
        const sig = Signature.decode(der);
        const pk = PublicKey.decode(sec);

        const valid = verify(pk, mod_tx_enc, sig);

        return valid;
    }

}

const ALPHABET_DECODE = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function address_to_pkb_hash(address){
    // given an address in b58check recover the public key hash
    let num = 0n;
    // (r1*58**str_len + ... + rn*58**0)
    for(let i = 0; i < address.length; i++){
        num *= 58n;
        num += BigInt(ALPHABET_DECODE.indexOf(address[i]));
    }
    // convert bigint to big endian byte
    const byte_address = (num.toString(16)).padStart(50, '0'); // 25 byte -> 50 hex
    // console.log(`byte address: ${byte_address}`);
    // validate the checksum
    // calculate the double sha256 of the first 21 bytes
    const checksum = sha256(sha256(byte_address.substring(0, 42)));
    // console.log(`checksum: ${checksum}`);
    if(byte_address.substring(42) !== checksum.substring(0, 8)){
        const show_alert = 'Address is not correct, Please check again';
        console.log(show_alert);
    }
    // strip the version in front and the checksum at tail
    const pkb_hash = byte_address.substring(2, 42);

    return pkb_hash;
}