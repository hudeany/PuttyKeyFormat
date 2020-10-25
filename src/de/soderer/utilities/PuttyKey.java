package de.soderer.utilities;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Container for PuTTY key data
 */
public class PuttyKey {
	private String comment;
	private final KeyPair keyPair;

	/**
	 * Create a PuTTY key with given keypair
	 */
	public PuttyKey(final String comment, final KeyPair keyPair) throws Exception {
		this.comment = comment;
		if (!"RSA".equals(keyPair.getPublic().getAlgorithm())
				&& !"DSA".equals(keyPair.getPublic().getAlgorithm())
				&& !"EC".equals(keyPair.getPublic().getAlgorithm())) {
			throw new IllegalArgumentException("Invalid public key algorithm for PuTTY key (only supports RSA / DSA / EC): " + keyPair.getPublic().getAlgorithm());
		}
		this.keyPair = keyPair;
	}

	/**
	 * Create a PuTTY key with given keydata
	 */
	public PuttyKey(final String comment, final String algorithmName, final byte[] privateKeyBytes, final byte[] publicKeyBytes) throws Exception {
		try {
			this.comment = comment;
			final BlockDataReader publicKeyReader = new BlockDataReader(publicKeyBytes);
			final String keyAlgorithmName = publicKeyReader.readString();
			if (keyAlgorithmName == null || !keyAlgorithmName.equalsIgnoreCase(algorithmName)) {
				throw new Exception("Corrupt public key data: Algorithm name in data differs from defined algorithm name. Expected \"" + algorithmName + "\", but was \"" + keyAlgorithmName + "\"");
			}
			final BlockDataReader privateKeyReader = new BlockDataReader(privateKeyBytes);

			if (KeyPairUtilities.SSH_ALGORITHM_NAME_RSA.equalsIgnoreCase(algorithmName)) {
				final BigInteger publicExponent = publicKeyReader.readBigInt();
				final BigInteger modulus = publicKeyReader.readBigInt();

				final BigInteger privateExponent = privateKeyReader.readBigInt();
				final BigInteger p = privateKeyReader.readBigInt(); // secret prime factor (= PrimeP)
				final BigInteger q = privateKeyReader.readBigInt(); // secret prime factor (= PrimeQ)
				final BigInteger iqmp = privateKeyReader.readBigInt(); // q^-1 mod p (= CrtCoefficient)

				final BigInteger dmp1 = privateExponent.mod(p.subtract(BigInteger.ONE)); // d mod (p-1) (= PrimeExponentP)
				final BigInteger dmq1 = privateExponent.mod(q.subtract(BigInteger.ONE)); // d mod (q-1) (= PrimeExponentQ)

				final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				final PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
				final PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, p, q, dmp1, dmq1, iqmp));
				keyPair = new KeyPair(publicKey, privateKey);
			} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_DSA.equalsIgnoreCase(algorithmName)) {
				final BigInteger p = publicKeyReader.readBigInt();
				final BigInteger q = publicKeyReader.readBigInt();
				final BigInteger g = publicKeyReader.readBigInt();

				// Public key exponent
				final BigInteger y = publicKeyReader.readBigInt();

				// Private key exponent
				final BigInteger x = privateKeyReader.readBigInt();

				final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
				final PublicKey publicKey = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
				final PrivateKey privateKey = keyFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
				keyPair = new KeyPair(publicKey, privateKey);
			} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)
					|| KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)
					|| KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
				final String curveName = publicKeyReader.readString();
				if ("nistp256".equals(curveName)) {
					// Do nothing
				} else if ("nistp384".equals(curveName)) {
					// Do nothing
				} else if ("nistp521".equals(curveName)) {
					// Do nothing
				} else {
					throw new Exception("Unsupported ECDSA curveName: " + curveName);
				}

				final byte[] qBytes = publicKeyReader.readData();
				final int xLength = (qBytes.length - 1) / 2;
				if (4 != qBytes[0]) {
					throw new Exception("Invalid key data found");
				}
				final byte[] x = new byte[xLength];
				final byte[] y = new byte[xLength];
				System.arraycopy(qBytes, 1, x, 0, xLength);
				System.arraycopy(qBytes, xLength + 1, y, 0, xLength);

				final KeyFactory keyFactory = KeyFactory.getInstance("EC");
				final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
				parameters.init(new ECGenParameterSpec(curveName.replace("nist", "sec") + "r1"));
				final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

				final BigInteger p = privateKeyReader.readBigInt();

				final PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)), ecParameterSpec));
				final PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(p, ecParameterSpec));

				keyPair = new KeyPair(publicKey, privateKey);
			} else {
				throw new IllegalArgumentException("Invalid public key algorithm for PuTTY key (only supports RSA / DSA / EC): " + algorithmName);
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read key data", e);
		}
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public String getAlgorithm() throws Exception {
		return KeyPairUtilities.getAlgorithm(keyPair);
	}

	public int getKeyStrength() throws Exception {
		return KeyPairUtilities.getKeyStrength(keyPair);
	}

	public String getComment() {
		return comment;
	}

	public void setComment(final String comment) {
		this.comment = comment;
	}

	public String getMd5Fingerprint() throws Exception {
		return KeyPairUtilities.getMd5Fingerprint(keyPair);
	}

	public String getSha256Fingerprint() throws Exception {
		return KeyPairUtilities.getSha256Fingerprint(keyPair);
	}

	/**
	 * Contains
	 *  ssh-rsa: RSAPublicKey and RSAPrivateCrtKey
	 *  ssh-dss: DSAPublicKey and DSAPrivateKey
	 */
	public KeyPair getKeyPair() throws Exception {
		return keyPair;
	}

	public byte[] getPublicKeyBytes() throws Exception {
		return KeyPairUtilities.getPublicKeyBytes(keyPair);
	}

	public byte[] getPrivateKeyBytes() throws Exception {
		return KeyPairUtilities.getPrivateKeyBytes(keyPair);
	}

	public String encodePublicKeyForAuthorizedKeys() throws Exception {
		return KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair);
	}

	private class BlockDataReader {
		private final DataInput keyDataInput;

		private BlockDataReader(final byte[] key) {
			keyDataInput = new DataInputStream(new ByteArrayInputStream(key));
		}

		private BigInteger readBigInt() throws Exception {
			return new BigInteger(readData());
		}

		private String readString() throws Exception {
			return new String(readData(), StandardCharsets.ISO_8859_1);
		}

		private byte[] readData() throws IOException, Exception {
			try {
				final int nextBlockSize = keyDataInput.readInt();
				if (nextBlockSize <= 0) {
					throw new Exception("Key blocksize error. Maybe the key encrytion password was wrong");
				}
				final byte[] nextBlock = new byte[nextBlockSize];
				keyDataInput.readFully(nextBlock);
				return nextBlock;
			} catch (final IOException e) {
				throw new Exception("Key block read error", e);
			}
		}
	}
}
