/**
 * 0x prefixed 20 bytes ethereum address encoded as hex string
 */
export type Address = string;

/**
 * A HexString whose length is even, which ensures it is a valid
 * representation of binary data.
 */
export type DataHexString = string;

/**
 * 64 bytes r, s signature values and v value
 */
export interface Signature {
  r: DataHexString;
  s: DataHexString;
  v?: 27 | 28;
}

/**
 * AWS KMS configuration options
 */
export interface AwsKmsSignerConfig {
  /** AWS KMS Key ID (UUID format) or Key ARN */
  keyId: string;

  /** AWS Region (e.g., 'us-east-1') */
  region?: string;

  /**
   * AWS Profile name (for local development)
   * If not provided, uses default credential chain (IAM roles in ECS/EC2)
   */
  profile?: string;

  /**
   * Optional: Explicit AWS credentials
   * If not provided, uses AWS SDK default credential chain
   */
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
}
