import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
} from '@aws-sdk/client-kms';
import { fromIni } from '@aws-sdk/credential-providers';
import {
  AbstractSigner,
  Provider,
  TransactionRequest,
  TypedDataDomain,
  TypedDataField,
  Transaction,
  Signature,
  resolveProperties,
  hashMessage,
  TypedDataEncoder,
  getBytes,
} from 'ethers';
import {
  getEthAddress,
  getRsSignature,
  determineCorrectV,
} from './crypto';
import { Address, AwsKmsSignerConfig } from './types';

/**
 * Ethers v6 signer implementation using AWS KMS
 *
 * Supports:
 * - Transaction signing
 * - Message signing
 * - EIP-712 typed data signing
 * - IAM roles (ECS/EC2)
 * - AWS profiles (local development)
 * - Explicit credentials
 */
export class AwsKmsSigner extends AbstractSigner {
  private address?: Address;
  private readonly keyId: string;
  private readonly client: KMSClient;

  constructor(config: AwsKmsSignerConfig, provider?: Provider) {
    super(provider);
    this.keyId = config.keyId;

    const region = config.region || process.env.AWS_REGION || 'us-east-1';

    // Configure KMS client with flexible credential options
    const clientConfig: any = { region };

    if (config.credentials) {
      // Explicit credentials provided
      clientConfig.credentials = config.credentials;
    } else if (config.profile) {
      // Use AWS profile (for local development)
      clientConfig.credentials = fromIni({ profile: config.profile });
    }
    // Otherwise, use default credential chain (IAM roles for ECS/EC2)

    this.client = new KMSClient(clientConfig);
  }

  /**
   * Connect this signer to a different provider
   */
  connect(provider: Provider): AwsKmsSigner {
    return new AwsKmsSigner(
      {
        keyId: this.keyId,
        region: this.client.config.region as string,
      },
      provider
    );
  }

  /**
   * Get the Ethereum address derived from the KMS public key
   */
  async getAddress(): Promise<Address> {
    if (this.address) {
      return this.address;
    }

    const { PublicKey } = await this.client.send(
      new GetPublicKeyCommand({ KeyId: this.keyId })
    );

    if (!PublicKey) {
      throw new Error('Could not get Public Key from AWS KMS');
    }

    this.address = getEthAddress(Buffer.from(PublicKey));
    return this.address;
  }

  /**
   * Sign a transaction
   */
  async signTransaction(txRequest: TransactionRequest): Promise<string> {
    const [{ from, to }, ethAddress] = await Promise.all([
      resolveProperties({ from: txRequest.from, to: txRequest.to }),
      this.getAddress(),
    ]);

    if (to != null) {
      txRequest.to = to;
    }

    if (from != null) {
      txRequest.from = from;
    }

    if (txRequest.from) {
      const fromStr = txRequest.from.toString();
      if (fromStr.toLowerCase() !== ethAddress.toLowerCase()) {
        throw new Error(`Transaction from address mismatch: ${fromStr} !== ${ethAddress}`);
      }
      delete txRequest.from;
    }

    const tx = Transaction.from(txRequest as any);
    tx.signature = await this._signDigest(tx.unsignedHash);
    return tx.serialized;
  }

  /**
   * Sign a message (personal_sign)
   */
  async signMessage(message: string | Uint8Array): Promise<string> {
    const digest = hashMessage(message);
    return this._signDigest(digest);
  }

  /**
   * Sign EIP-712 typed data
   */
  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, any>
  ): Promise<string> {
    const digest = TypedDataEncoder.hash(domain, types, value);
    return this._signDigest(digest);
  }

  /**
   * Internal: Sign a digest using AWS KMS
   */
  private async _signDigest(digestHex: string): Promise<string> {
    const digestBuf = Buffer.from(getBytes(digestHex));
    const [{ r, s }, ethAddress] = await Promise.all([
      this._rawKmsSign(digestBuf),
      this.getAddress(),
    ]);

    const v = determineCorrectV(digestBuf, r, s, ethAddress);
    return Signature.from({ r, s, v }).serialized;
  }

  /**
   * Internal: Perform raw KMS signing operation
   */
  private async _rawKmsSign(digest: Buffer): Promise<{ r: string; s: string }> {
    const { Signature: sigBytes } = await this.client.send(
      new SignCommand({
        KeyId: this.keyId,
        SigningAlgorithm: 'ECDSA_SHA_256',
        MessageType: 'DIGEST',
        Message: digest,
      })
    );

    if (!sigBytes) {
      throw new Error('Could not get signature from AWS KMS');
    }

    return getRsSignature(Buffer.from(sigBytes));
  }
}
