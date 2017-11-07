import WebCrypto = require('node-webcrypto-ossl');
import * as asn1js from 'asn1js';
import pkijs = require('pkijs');
import * as nodeSpecificCrypto from './node-crypto';

const {
    Certificate,
    CryptoEngine,
    setEngine,
    getCrypto,
    AttributeTypeAndValue,
    BasicConstraints,
    Extension,
    getAlgorithmParameters
} = pkijs;

const webcrypto = new WebCrypto();

setEngine('nodeEngine', nodeSpecificCrypto, new CryptoEngine({
    crypto: nodeSpecificCrypto,
    subtle: webcrypto.subtle,
    name: 'nodeEngine'
}));

const hashAlg = 'SHA-1';
const signAlg = 'RSASSA-PKCS1-v1_5';

function btoa(str) {
    let buffer;

    if (str instanceof Buffer) {
        buffer = str;
    } else {
        buffer = new Buffer(str.toString(), 'binary');
    }

    return buffer.toString('base64');
}

async function createCertificateInternal(): Promise<{
    certificate: ArrayBuffer;
    privateKey: ArrayBuffer
}> {

    const certificate = new Certificate();

    const crypto = getCrypto();
    if (typeof crypto === 'undefined') {
        return Promise.reject('No WebCrypto extension found');
    }

    certificate.version = 2;
    certificate.serialNumber = new asn1js.Integer({ value: 1 });
    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.6', // Country name
        value: new asn1js.PrintableString({ value: 'RU' })
    }));
    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', // Common name
        value: new asn1js.BmpString({ value: 'Test' })
    }));
    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.6', // Country name
        value: new asn1js.PrintableString({ value: 'RU' })
    }));
    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', // Common name
        value: new asn1js.BmpString({ value: 'Test' })
    }));

    certificate.notBefore.value = new Date(2016, 1, 1);
    certificate.notAfter.value = new Date(2019, 1, 1);

    // Extensions are not a part of certificate by default, it's an optional array
    certificate.extensions = [];

    const basicConstr = new BasicConstraints({
        cA: true,
        pathLenConstraint: 3
    });

    certificate.extensions.push(new Extension({
        extnID: '2.5.29.19',
        critical: true,
        extnValue: basicConstr.toSchema().toBER(false),
        parsedValue: basicConstr // Parsed value for well-known extensions
    }));

    const bitArray = new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);

    // tslint:disable-next-line:no-bitwise
    bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
    // tslint:disable-next-line:no-bitwise
    bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag

    const keyUsage = new asn1js.BitString({ valueHex: bitArray });

    certificate.extensions.push(new Extension({
        extnID: '2.5.29.15',
        critical: false,
        extnValue: keyUsage.toBER(false),
        parsedValue: keyUsage // Parsed value for well-known extensions
    }));

    // create a new key pair
    const algorithm = getAlgorithmParameters(signAlg, 'generatekey');
    if ('hash' in algorithm.algorithm) {
        algorithm.algorithm.hash.name = hashAlg;
    }

    let keyPair = null;

    try {
        keyPair = await crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    } catch (error) {
        throw new Error(`Error during key generation: ${error}`);
    }

    const publicKey = keyPair.publicKey;
    const privateKey = keyPair.privateKey;

    // Exporting public key into "subjectPublicKeyInfo" value of certificate
    await certificate.subjectPublicKeyInfo.importKey(publicKey);

    try {
        // signing final certificate
        await certificate.sign(privateKey, hashAlg);
    } catch (error) {
        throw new Error(`Error during signing: ${error}`);
    }

    // Encode certificate
    const certificateBuffer = certificate.toSchema(true).toBER(false);

    try {
        const privateKeyBuffer = await crypto.exportKey('pkcs8', privateKey);

        return {
            certificate: certificateBuffer,
            privateKey: privateKeyBuffer
        };

    } catch (error) {
        throw new Error(`Error during exporting of private key: ${error}`);
    }
}

function formatPEM(pemString) {
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pemString" type="String">String to format</param>

    const stringLength = pemString.length;
    let resultString = '';

    for (let i = 0, count = 0; i < stringLength; i++ , count++) {
        if (count > 63) {
            resultString = `${resultString}\r\n`;
            count = 0;
        }

        resultString = `${resultString}${pemString[i]}`;
    }

    return resultString;
}

async function createCertificate() {

    const { certificate, privateKey } = await createCertificateInternal();

    const certificateString =
        String.fromCharCode.apply(null, new Uint8Array(certificate));

    let resultString = '-----BEGIN CERTIFICATE-----\r\n';
    resultString = `${resultString}${formatPEM(btoa(certificateString))}`;
    resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;

    console.log('Certificate created successfully!');

    const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(privateKey));

    resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
    resultString = `${resultString}${formatPEM(btoa(privateKeyString))}`;
    resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;

    console.log(resultString);

    console.log('Private key exported successfully!');
}

createCertificate();
