# @startengine/ethers-v6-kms-signer

Ethers v6 signer implementation using AWS KMS for secure blockchain transaction signing. Supports IAM roles, credential chains, and EIP-712 typed data signing for EVM-compatible chains.

## Features

- ✅ **Ethers v6 Compatible** - Extends `AbstractSigner` from ethers v6
- ✅ **Flexible Credentials** - Supports IAM roles, AWS profiles, and explicit credentials
- ✅ **EIP-712 Support** - Sign typed data for protocols like Uniswap, OpenSea, etc.
- ✅ **Transaction Signing** - Sign EVM transactions with AWS KMS
- ✅ **Message Signing** - Sign arbitrary messages (personal_sign)
- ✅ **Production Ready** - Works in both local development and AWS ECS/EC2

## Installation

```bash
npm install @startengine/ethers-v6-kms-signer
```

## Prerequisites

### AWS KMS Key Requirements

Your AWS KMS key must be:
- **Asymmetric** key type
- **Sign and verify** usage
- **ECC_SECG_P256K1** key spec (secp256k1 curve for Ethereum)

### IAM Permissions

The entity using this library needs the following permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:GetPublicKey",
    "kms:Sign"
  ],
  "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
}
```

## Usage

### Basic Usage (IAM Roles - Recommended for Production)

In AWS ECS/EC2, the SDK automatically uses IAM roles:

```typescript
import { AwsKmsSigner } from '@startengine/ethers-v6-kms-signer';
import { JsonRpcProvider } from 'ethers';

const provider = new JsonRpcProvider('https://polygon-rpc.com');

const signer = new AwsKmsSigner(
  {
    keyId: '4a7aa1b7-058c-4153-80f0-959cb94a500f', // KMS Key ID
    region: 'us-east-1',
  },
  provider
);

// Get address
const address = await signer.getAddress();
console.log('Signer address:', address);

// Send transaction
const tx = await signer.sendTransaction({
  to: '0x...',
  value: ethers.parseEther('0.1'),
});
```

### Local Development (AWS Profile)

For local development with AWS profiles:

```typescript
const signer = new AwsKmsSigner(
  {
    keyId: '4a7aa1b7-058c-4153-80f0-959cb94a500f',
    region: 'us-east-1',
    profile: 'my-aws-profile', // References ~/.aws/credentials
  },
  provider
);
```

### Explicit Credentials

If you need to provide credentials explicitly:

```typescript
const signer = new AwsKmsSigner(
  {
    keyId: '4a7aa1b7-058c-4153-80f0-959cb94a500f',
    region: 'us-east-1',
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
  },
  provider
);
```

### Sign Messages

```typescript
const signature = await signer.signMessage('Hello, World!');
```

### Sign EIP-712 Typed Data

```typescript
const domain = {
  name: 'MyDapp',
  version: '1',
  chainId: 137,
  verifyingContract: '0x...',
};

const types = {
  Person: [
    { name: 'name', type: 'string' },
    { name: 'wallet', type: 'address' },
  ],
};

const value = {
  name: 'Alice',
  wallet: '0x...',
};

const signature = await signer.signTypedData(domain, types, value);
```

### Deploy Contracts

```typescript
import { ContractFactory } from 'ethers';

const factory = new ContractFactory(abi, bytecode, signer);
const contract = await factory.deploy(...constructorArgs);
await contract.waitForDeployment();
```

## Configuration Options

```typescript
interface AwsKmsSignerConfig {
  /** AWS KMS Key ID (UUID) or ARN */
  keyId: string;

  /** AWS Region (default: us-east-1) */
  region?: string;

  /** AWS Profile for local development */
  profile?: string;

  /** Explicit AWS credentials (optional) */
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
}
```

## Credential Resolution Order

The signer resolves credentials in this order:

1. **Explicit credentials** - If provided in config
2. **AWS Profile** - If `profile` specified
3. **Default credential chain**:
   - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
   - IAM role (ECS task role, EC2 instance profile)
   - AWS credentials file (`~/.aws/credentials`)

## Environment Variables

```bash
# AWS Region
AWS_REGION=us-east-1

# For explicit credential auth
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# For profile-based auth (local development)
AWS_PROFILE=my-profile
```

## Security Best Practices

1. **Use IAM Roles in Production** - Don't hardcode credentials
2. **Principle of Least Privilege** - Only grant `kms:GetPublicKey` and `kms:Sign`
3. **Key Rotation** - Regularly rotate KMS keys
4. **CloudTrail Logging** - Enable logging for KMS operations
5. **Network Isolation** - Use VPC endpoints for KMS in production

## License

MIT

## Author

StartEngine
