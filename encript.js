 const  cipher =  require("./lib/aes_lib")
function encrypt (plaintext,password) {
   let  plaintexti = utf8Encode(String(plaintext));
    password = utf8Encode(String(password)).toString();
    console.log(plaintexti)

     

    
    const nBytes = 16; 
    const pwBytes = new Array(nBytes);
    for (let i=0; i<nBytes; i++) { 
        pwBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
    }
    let key = cipher.createStates(pwBytes,cipher.expandKey(pwBytes));

    const timestamp = (new Date()).getTime(); // milliseconds since 1-Jan-1970
    const nonceMs = timestamp%1000;
    const nonceSec = Math.floor(timestamp/1000);
    const nonceRnd = Math.floor(Math.random()*0xffff);
    // for debugging: const [ nonceMs, nonceSec, nonceRnd ] = [ 0, 0, 0 ];
    const counterBlock = [ // 16-byte array; blocksize is fixed at 16 for AES
        nonceMs  & 0xff, nonceMs >>>8 & 0xff,
        nonceRnd & 0xff, nonceRnd>>>8 & 0xff,
        nonceSec & 0xff, nonceSec>>>8 & 0xff, nonceSec>>>16 & 0xff, nonceSec>>>24 & 0xff,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    
    const nonceStr = counterBlock.slice(0, 8).map(i => String.fromCharCode(i)).join('');

    
    plaintexti = plaintexti.toString()
    const plaintextBytes = plaintexti.split('').map(ch => ch.charCodeAt(0));


    const ciphertextBytes = preEncryptionFunc(plaintextBytes, key, counterBlock);

    // convert byte array to (utf-8) ciphertext string
    const ciphertextUtf8 = ciphertextBytes.map(i => String.fromCharCode(i)).join('');

    // base-64 encode ciphertext
    console.log(`g ${ciphertextUtf8}`)
    const ciphertextB64 = base64Encode(ciphertextUtf8);

    return ciphertextB64;
}

 
 

 
 function preEncryptionFunc(plaintext, key, counterBlock) {
    const block_Size = 16;

     
    const keySchedule = cipher.expandKey(key);

    const blockCount = Math.ceil(plaintext.length/block_Size);
    const ciphertext = new Array(plaintext.length);

    for (let b=0; b<blockCount; b++) {
        
        const cipherCntr = cipher.createStates(counterBlock, keySchedule);

        const blockLength = b<blockCount-1 ? block_Size : (plaintext.length-1)%block_Size + 1;

    
        for (let i=0; i<blockLength; i++) {
            ciphertext[b*block_Size + i] = cipherCntr[i] ^ plaintext[b*block_Size + i];
        }

        // increment counter block (counter in 2nd 8 bytes of counter block, big-endian)
        counterBlock[block_Size-1]++;
        // and propagate carry digits
        for (let i=block_Size-1; i>=8; i--) {
            counterBlock[i-1] += counterBlock[i] >> 8;
            counterBlock[i] &= 0xff;
        }

    
    return ciphertext;
}
 }

 function base64Encode(str) {
    if (typeof btoa != 'undefined') return btoa(str); // browser
    if (typeof Buffer != 'undefined') return new Buffer(str, 'base64') // Node.js
    throw new Error('No Base64 Encode');
}


function utf8Encode(str) {
    try {
        return new Buffer.from(str,"utf-8");
    } catch (e) { 
        return "no text available"
    }
}

console.log(encrypt("marenga bfjef dfd fdhfd fsnfbsjfs fj sjfbs fshfs fsbfs fsbfs fsbfs fjsf sfbsf sfjsbfsfjsds d","amelowalowakabis"))

 