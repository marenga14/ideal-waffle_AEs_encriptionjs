const  cipher =  require("./lib/aes_lib")

function decrypt(ciphertext, password) {
    
    ciphertext = base64Decode(String(ciphertext))
    console.log(ciphertext)
    password = Buffer.from(password,"utf8")

    // use AES to encrypt password (mirroring encrypt routine)
    const nBytes = 16; 
    const pwBytes = new Array(nBytes);
    password = password.toString();
    for (let i=0; i<nBytes; i++) {
        pwBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
    }
    let key = cipher.createStates(pwBytes, cipher.expandKey(pwBytes));
 

    // recover nonce from 1st 8 bytes of ciphertext into 1st 8 bytes of counter block
    const counterBlock = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
    for (let i=0; i<8; i++) counterBlock[i] = ciphertext.charCodeAt(i);

    // convert ciphertext to byte array (skipping past initial 8 bytes)
    const ciphertextBytes = new Array(ciphertext.length-8);
    for (let i=8; i<ciphertext.length; i++) ciphertextBytes[i-8] = ciphertext.charCodeAt(i);

    console.log(ciphertextBytes)


    const plaintextBytes = preDecryption(ciphertextBytes, key, counterBlock);
    console.log(plaintextBytes)

    
    const plaintextUtf8 = plaintextBytes.map(i => String.fromCharCode(i)).join('');
    console.log(plaintextUtf8)
    
    const plaintext = utf8Decode(plaintextUtf8);

    return plaintext;
}

 
function preDecryption(ciphertext, key, counterBlock) {
    const blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES

    // generate key schedule - an expansion of the key into distinct Key Rounds for each round
    const keySchedule = cipher.expandKey(key);

    const blockCount = Math.ceil(ciphertext.length/blockSize);
    const plaintext = new Array(ciphertext.length);

    for (let b=0; b<blockCount; b++) {
    
        const cipherCntr = cipher.createStates(counterBlock, keySchedule);

    
        const blockLength = b<blockCount-1 ? blockSize : (ciphertext.length-1)%blockSize + 1;

    
        for (let i=0; i<blockLength; i++) {
            plaintext[b*blockSize + i] = cipherCntr[i] ^ ciphertext[b*blockSize + i];
        }

        
        counterBlock[blockSize-1]++;
        // and propagate carry digits
        for (let i=blockSize-1; i>=8; i--) {
            counterBlock[i-1] += counterBlock[i] >> 8;
            counterBlock[i] &= 0xff;
        }

        
    }

    return plaintext;
}

function base64Decode(str) {
    if (typeof atob != 'undefined') return atob(str); // browser
    if (typeof Buffer != 'undefined') return new Buffer(str, 'base64').toString('utf-8'); 
    throw new Error('No Base64 Decode');
}

function utf8Decode(str) {
    try {
        return str.toString();
    } catch (e) { // no TextEncoder available?
        return "no text available"
    }
}





let word = decrypt("ARZ7CzXEQSxdadZd","amelowalowakabis")

 