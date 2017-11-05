// tslint:disable-next-line:no-var-requires
const WebCrypto = require('node-webcrypto-ossl');

import * as asn1js from 'asn1js';
import { stringToArrayBuffer, arrayBufferToString, fromBase64, toBase64 } from 'pvutils';
import pkijs = require('pkijs');

const Certificate = pkijs.Certificate;
const AttributeCertificateV1 = pkijs.AttributeCertificateV1;
const PrivateKeyInfo = pkijs.PrivateKeyInfo;
const AuthenticatedSafe = pkijs.AuthenticatedSafe;
const SafeContents = pkijs.SafeContents;
const SafeBag = pkijs.SafeBag;
const CertBag = pkijs.CertBag;
const PFX = pkijs.PFX;
const Attribute = pkijs.Attribute;
const PKCS8ShroudedKeyBag = pkijs.PKCS8ShroudedKeyBag;
const AttributeTypeAndValue = pkijs.AttributeTypeAndValue;
const BasicConstraints = pkijs.BasicConstraints;
const Extension = pkijs.Extension;

const getAlgorithmParameters = pkijs.getAlgorithmParameters;
const getRandomValues = pkijs.getRandomValues;
const setEngine = pkijs.setEngine;
const getCrypto = pkijs.getCrypto;
const getEngine = pkijs.getEngine;
const CryptoEngine = pkijs.CryptoEngine;

const webcrypto = new WebCrypto();

import * as nodeSpecificCrypto from './node-crypto';

setEngine('nodeEngine', nodeSpecificCrypto, new CryptoEngine({
    crypto: nodeSpecificCrypto,
    subtle: webcrypto.subtle,
    name: 'nodeEngine'
}));

// console.log(getEngine());

let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
let privateKeyBuffer = new ArrayBuffer(0);
let trustedCertificates = []; // Array of root certificates from "CA Bundle"
const intermadiateCertificates = []; // Array of intermediate certificates
const crls = []; // Array of CRLs for all certificates (trusted + intermediate)

const hashAlg = 'SHA-1';
const signAlg = 'RSASSA-PKCS1-v1_5';

function createCertificateInternal() {
    // region Initial variables
    let sequence: Promise<any> = Promise.resolve();

    const certificate = new Certificate();

    let publicKey;
    let privateKey;

    trustedCertificates = [];
    // endregion

    // region Get a "crypto" extension
    const crypto = getCrypto();
    if (typeof crypto === 'undefined') {
        return Promise.reject('No WebCrypto extension found');
    }
    // endregion

    // region Put a static values
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

    // region "BasicConstraints" extension
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
    // endregion

    // region "KeyUsage" extension
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
    // endregion
    // endregion

    // region Create a new key pair
    sequence = sequence.then(() => {
        // region Get default algorithm parameters for key generation
        const algorithm = getAlgorithmParameters(signAlg, 'generatekey');
        if ('hash' in algorithm.algorithm) {
            algorithm.algorithm.hash.name = hashAlg;
        }
        // endregion

        return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    });
    // endregion

    // region Store new key in an interim variables
    sequence = sequence.then((keyPair) => {
        publicKey = keyPair.publicKey;
        privateKey = keyPair.privateKey;
    }, (error) => Promise.reject(`Error during key generation: ${error}`));
    // endregion

    // region Exporting public key into "subjectPublicKeyInfo" value of certificate
    sequence = sequence.then(() =>
        certificate.subjectPublicKeyInfo.importKey(publicKey)
    );
    // endregion

    // region Signing final certificate
    sequence = sequence.then(() =>
        certificate.sign(privateKey, hashAlg),
        (error) => Promise.reject(`Error during exporting public key: ${error}`));
    // endregion

    // region Encode and store certificate
    sequence = sequence.then(() => {
        trustedCertificates.push(certificate);
        certificateBuffer = certificate.toSchema(true).toBER(false);
    }, (error) => Promise.reject(`Error during signing: ${error}`));
    // endregion

    // region Exporting private key
    sequence = sequence.then(() =>
        crypto.exportKey('pkcs8', privateKey)
    );
    // endregion

    // region Store exported key on Web page
    sequence = sequence.then((result) => {
        privateKeyBuffer = result;
    }, (error) => Promise.reject(`Error during exporting of private key: ${error}`));
    // endregion

    return sequence;
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

function createCertificate() {
    return createCertificateInternal().then(() => {
        const certificateString =
            String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));

        const base64Str = Buffer.from(certificateString).toString('base64');

        let resultString = '-----BEGIN CERTIFICATE-----\r\n';
        resultString = `${resultString}${formatPEM(base64Str)}`;
        resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;

        console.log('Certificate created successfully!');

        const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(privateKeyBuffer));

        const base64Str2 = Buffer.from(privateKeyString).toString('base64');

        resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
        resultString = `${resultString}${formatPEM(base64Str2)}`;
        resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;

        // document.getElementById("new_signed_data").innerHTML = resultString;

        console.log(resultString);

        console.log('Private key exported successfully!');
    }, (error) => {
        if (error instanceof Object) {
            console.log(error.message);
        } else {
            console.log(error);
        }
    });
}

createCertificate();
