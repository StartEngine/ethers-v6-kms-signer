// @ts-ignore - asn1.js doesn't have type definitions
import * as asn1 from 'asn1.js';
import { keccak256, getAddress, recoverAddress } from 'ethers';

/**
 * ASN.1 DER parse ECDSA Signature
 * @see https://tools.ietf.org/html/rfc3279#section-2.2.3
 */
export const EcdsaSigAsnParse = asn1.define('EcdsaSig', function (this: any) {
  this.seq().obj(this.key('r').int(), this.key('s').int());
});

/**
 * ASN.1 DER parse ECDSA Public Key
 * @see https://tools.ietf.org/html/rfc5480#section-2
 */
const EcdsaPubKey = asn1.define('EcdsaPubKey', function (this: any) {
  this.seq().obj(
    this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()),
    this.key('pubKey').bitstr()
  );
});

/**
 * Returns decoded r, s signature in BigInt
 */
export const decodeEcdsaSig = (signature: Buffer): { r: bigint; s: bigint } => {
  // r & s values are in BN.js format
  const { r, s } = EcdsaSigAsnParse.decode(signature, 'der');
  return {
    r: BigInt(`0x${r.toString(16)}`),
    s: BigInt(`0x${s.toString(16)}`),
  };
};

/**
 * Returns the (04) prefixed 65 bytes public key
 */
export const decodeEcdsaPubKey = (publicKey: Buffer): Buffer => {
  const { pubKey } = EcdsaPubKey.decode(publicKey, 'der');
  return pubKey.data;
};

/**
 * Converts the given bigint value to hex (adds 0 padding as necessary)
 */
export const toHex = (bigIntValue: bigint): string => {
  let hex = bigIntValue.toString(16);
  // add 0 padding if not even length
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  return '0x' + hex;
};

/**
 * Retrieves the 0x prefixed 20 byte Ethereum address from the given public key
 *
 * The public key returned is ASN1 encoded in the format as defined below
 * @see https://tools.ietf.org/html/rfc5480#section-2
 *
 * The raw public key starts with a 0x04 prefix that needs to be removed
 * @see https://github.com/ethereumbook/ethereumbook/blob/develop/04keys-addresses.asciidoc
 */
export const getEthAddress = (publicKeyDer: Buffer): string => {
  const decodedPublicKey = decodeEcdsaPubKey(publicKeyDer);
  // Drop the first byte (04) prefix
  const noPrefixPublicKey = decodedPublicKey.subarray(1, decodedPublicKey.length);
  // the last 20 bytes (40 hexits) of the pub key hash is the ethereum address
  const address = `0x${keccak256(noPrefixPublicKey).slice(-40)}`;
  // return checksummed address
  return getAddress(address);
};

/**
 * Returns the 64 bytes r & s signature values, adjusts s signature as necessary (EIP-2)
 *
 * EIP-2 spec.2:
 * The value of `s` needs to be SMALLER than half of the curve
 * if `s` is greater than half of the curve, flip `s` to get the valid `s` value
 * @see https://eips.ethereum.org/EIPS/eip-2
 */
export const getRsSignature = (
  signature: Buffer
): { r: string; s: string } => {
  const { r, s } = decodeEcdsaSig(signature);

  // Max curve / half curve values (secp256k1)
  const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  const secp256k1halfN = secp256k1N / BigInt(2);

  return {
    r: toHex(r),
    s: toHex(s > secp256k1halfN ? secp256k1N - s : s), // flip s if > than half of the curve
  };
};

/**
 * Helper function to compute recovered address from msg and signature and compares it with expected address
 */
export const isCorrectV = (
  expectedEthAddr: string,
  msg: Buffer,
  r: string,
  s: string,
  v: number
): boolean => {
  const recoveredAddress = recoverAddress(msg, { r, s, v });
  return recoveredAddress.toLowerCase() === expectedEthAddr.toLowerCase();
};

/**
 * Find the right v value between two matching signatures on the elliptic curve (v = 27 or 28)
 */
export const determineCorrectV = (
  msg: Buffer,
  r: string,
  s: string,
  expectedEthAddr: string
): number => {
  if (isCorrectV(expectedEthAddr, msg, r, s, 27)) {
    return 27;
  }
  if (isCorrectV(expectedEthAddr, msg, r, s, 28)) {
    return 28;
  }
  throw new Error('Could not determine correct v value for signature');
};
