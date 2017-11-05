import * as crypto from 'crypto';
// tslint:disable-next-line:no-var-requires
const WebCrypto = require('node-webcrypto-ossl');

const webcrypto = new WebCrypto();

export function getRandomValues(length: number) {
    return (new Uint8Array(crypto.randomBytes(length)));
}

export function encryptUsingPBKDF2Password(
    algorithm: string,
    keyLength: number,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterationCount: number,
    hashAlgorithm: string,
    iv: ArrayBuffer,
    messageToEncrypt: ArrayBuffer) {

    let cipher;

    hashAlgorithm = hashAlgorithm.replace('-', '');

    const key = crypto.pbkdf2Sync(
        Buffer.from(password), Buffer.from(salt), iterationCount, keyLength, hashAlgorithm);

    if (iv.byteLength) {
        cipher = crypto.createCipheriv(algorithm, key, Buffer.from(iv));
    } else {
        cipher = crypto.createCipher(algorithm, key);
    }

    return (new Uint8Array(
        Buffer.concat([cipher.update(Buffer.from(messageToEncrypt)), cipher.final()]))).buffer;
}

export function decryptUsingPBKDF2Password(
    algorithm: string,
    keyLength: number,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterationCount: number,
    hashAlgorithm: string,
    iv: ArrayBuffer,
    messageToDecrypt: ArrayBuffer) {

    let cipher;

    hashAlgorithm = hashAlgorithm.replace('-', '');

    const key = crypto.pbkdf2Sync(
        Buffer.from(password), Buffer.from(salt), iterationCount, keyLength, hashAlgorithm);

    if (iv.byteLength) {
        cipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv));
    } else {
        cipher = crypto.createDecipher(algorithm, key);
    }

    return (new Uint8Array(
        Buffer.concat([cipher.update(Buffer.from(messageToDecrypt)), cipher.final()]))).buffer;
}

export function makePKCS12B2Key(
    hashAlgorithm: string,
    keyLength: number,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterationCount: number) {

    let u;
    let v;

    const result = [];

    switch (hashAlgorithm.toUpperCase()) {
        case 'SHA1':
            u = 20; // 160
            v = 64; // 512
            break;
        case 'SHA256':
            u = 32; // 256
            v = 64; // 512
            break;
        case 'SHA384':
            u = 48; // 384
            v = 128; // 1024
            break;
        case 'SHA512':
            u = 64; // 512
            v = 128; // 1024
            break;
        default:
            throw new Error('Unsupported hashing algorithm');
    }

    const passwordViewInitial = new Uint8Array(password);
    const passwordTransformed = new ArrayBuffer((password.byteLength * 2) + 2);
    const passwordTransformedView = new Uint8Array(passwordTransformed);

    for (let i = 0; i < passwordViewInitial.length; i++) {
        passwordTransformedView[i * 2] = 0x00;
        passwordTransformedView[i * 2 + 1] = passwordViewInitial[i];
    }

    passwordTransformedView[passwordTransformedView.length - 2] = 0x00;
    passwordTransformedView[passwordTransformedView.length - 1] = 0x00;

    password = passwordTransformed.slice(0);

    const D = new ArrayBuffer(v);
    const dView = new Uint8Array(D);

    for (let i = 0; i < D.byteLength; i++) {
        dView[i] = 3;
    } // The ID value equal to "3" for MACing (see B.3 of standard)

    // region Concatenate copies of the salt together to
    // create a string S of length v * ceil(s / v) bytes
    // (the final copy of the salt may be trunacted to create S)
    const saltLength = salt.byteLength;

    const sLen = v * Math.ceil(saltLength / v);
    const S = new ArrayBuffer(sLen);
    const sView = new Uint8Array(S);

    const saltView = new Uint8Array(salt);

    for (let i = 0; i < sLen; i++) {
        sView[i] = saltView[i % saltLength];
    }
    // endregion

    // region Concatenate copies of the password
    // together to create a string P of length v * ceil(p / v)
    // bytes (the final copy of the password may be truncated to create P)
    const passwordLength = password.byteLength;

    const pLen = v * Math.ceil(passwordLength / v);
    const P = new ArrayBuffer(pLen);
    const pView = new Uint8Array(P);

    const passwordView = new Uint8Array(password);

    for (let i = 0; i < pLen; i++) {
        pView[i] = passwordView[i % passwordLength];
    }
    // endregion

    // region Set I=S||P to be the concatenation of S and P
    const sPlusPLength = S.byteLength + P.byteLength;

    let I = new ArrayBuffer(sPlusPLength);
    let iView = new Uint8Array(I);

    iView.set(sView);
    iView.set(pView, sView.length);
    // endregion

    // region Set c=ceil(n / u)
    // tslint:disable-next-line:no-bitwise
    const c = Math.ceil((keyLength >> 3) / u);
    // endregion

    // region For i=1, 2, ..., c, do the following:
    for (let i = 0; i <= c; i++) {
        // region Create contecanetion of D and I
        const dAndI = new ArrayBuffer(D.byteLength + I.byteLength);
        const dAndIView = new Uint8Array(dAndI);

        dAndIView.set(dView);
        dAndIView.set(iView, dView.length);
        // endregion

        // region Make "iterationCount" rounds of hashing
        let roundBuffer = Buffer.from(dAndI);

        for (let j = 0; j < iterationCount; j++) {
            const hash = crypto.createHash(hashAlgorithm);
            hash.update(roundBuffer);
            roundBuffer = hash.digest();
        }
        // endregion

        // region Concatenate copies of Ai to create a string B of
        // length v bits (the final copy of Ai may be truncated to create B)
        const B = new ArrayBuffer(v);
        const bView = new Uint8Array(B);

        for (let j = 0; j < B.byteLength; j++) {
            bView[j] = roundBuffer[j % roundBuffer.length];
        }
        // endregion

        // region Make new I value
        const k = Math.ceil(saltLength / v) + Math.ceil(passwordLength / v);
        const iRound = [];

        let sliceStart = 0;
        let sliceLength = v;

        for (let j = 0; j < k; j++) {
            const chunk = Array.from(new Uint8Array(I.slice(sliceStart, sliceStart + sliceLength)));
            sliceStart += v;
            if ((sliceStart + v) > I.byteLength) {
                sliceLength = I.byteLength - sliceStart;
            }

            let x = 0x1ff;

            for (let l = (B.byteLength - 1); l >= 0; l--) {
                // tslint:disable-next-line:no-bitwise
                x = x >> 8;
                x += bView[l] + chunk[l];
                // tslint:disable-next-line:no-bitwise
                chunk[l] = (x & 0xff);
            }

            iRound.push(...chunk);
        }

        I = new ArrayBuffer(iRound.length);
        iView = new Uint8Array(I);

        iView.set(iRound);
        // endregion

        result.push(...roundBuffer);
    }
    // endregion

    // region Initialize final key
    // tslint:disable-next-line:no-bitwise
    const resultBuffer = new ArrayBuffer(keyLength >> 3);
    const resultView = new Uint8Array(resultBuffer);

    // tslint:disable-next-line:no-bitwise
    resultView.set((new Uint8Array(result)).slice(0, keyLength >> 3));
    // endregion
    // endregion

    return Buffer.from(resultBuffer);
}

export function stampDataWithPassword(
    hashAlgorithm: string,
    keyLength: number,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterationCount: number,
    stampingData: ArrayBuffer,
    method?: string) {

    let key;

    if (method === undefined) {
        method = 'pkcs12';
    }

    hashAlgorithm = hashAlgorithm.replace('-', '');

    // region Derive key using PKCS#12 algorithm from B.2 item of standard
    switch (method.toLowerCase()) {
        case 'pbkdf2':
            key = crypto.pbkdf2Sync(
                Buffer.from(password), Buffer.from(salt), iterationCount, keyLength, hashAlgorithm);
            break;
        case 'pkcs12':
        default:
            key = makePKCS12B2Key(hashAlgorithm, keyLength, password, salt, iterationCount);
    }
    // endregion

    const hmac = crypto.createHmac(hashAlgorithm, key);
    hmac.update(Buffer.from(stampingData));

    return (new Uint8Array(hmac.digest())).buffer;
}

export function verifyDataStampedWithPassword(
    hashAlgorithm: string,
    keyLength: number,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterationCount: number,
    stampedData: ArrayBuffer,
    signatureToVerify: ArrayBuffer,
    method?: string) {

    let key;

    if (method === undefined) {
        method = 'pkcs12';
    }

    hashAlgorithm = hashAlgorithm.replace('-', '');

    // region Derive key using PKCS#12 algorithm from B.2 item of standard
    switch (method.toLowerCase()) {
        case 'pbkdf2':
            key = crypto.pbkdf2Sync(
                Buffer.from(password), Buffer.from(salt), iterationCount, keyLength, hashAlgorithm);
            break;
        case 'pkcs12':
        default:
            key = makePKCS12B2Key(hashAlgorithm, keyLength, password, salt, iterationCount);
    }
    // endregion

    const hmac = crypto.createHmac(hashAlgorithm, key);
    hmac.update(Buffer.from(stampedData));
    const hmacValue = new Uint8Array(hmac.digest());

    // region Compare HMAC digest with signature to verify
    const dataView = new Uint8Array(signatureToVerify);

    if (hmacValue.length !== dataView.length) {
        return false;
    }

    let result = true;

    for (let i = 0; i < hmacValue.length; i++) {
        if (hmacValue[i] !== dataView[i]) {
            result = false;
            break;
        }
    }

    return result;
}

export const subtle = webcrypto.subtle;
