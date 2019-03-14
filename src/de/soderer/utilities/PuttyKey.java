package de.soderer.utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Container for PuTTY key data
 */
public class PuttyKey {
	public static String SSH_CIPHER_NAME_RSA = "ssh-rsa";
	public static String SSH_CIPHER_NAME_DSA = "ssh-dss";
	public static String SSH_CIPHER_NAME_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";
	public static String SSH_CIPHER_NAME_ECDSA_NISTP384 = "ecdsa-sha2-nistp384";
	public static String SSH_CIPHER_NAME_ECDSA_NISTP521 = "ecdsa-sha2-nistp521";

	private String comment;
	private final KeyPair keyPair;

	/**
	 * Create a RSA PuTTY key of given strength
	 */
	public PuttyKey(final String comment, final int keyStrength) throws Exception {
		if (keyStrength < 512) {
			throw new Exception("Invalid RSA key strength: " + keyStrength);
		}
		this.comment = comment;
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keyStrength);
		keyPair = keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a DSA PuTTY key of standard 1024 bit strength
	 */
	public PuttyKey(final String comment) throws Exception {
		this.comment = comment;
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPair = keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a ECDSA PuTTY key of eliptic curve name.
	 * Supported eliptic curve names are
	 *   nistp256 or secp256
	 *   nistp384 or secp384
	 *   nistp521 or secp521
	 */
	public PuttyKey(final String comment, final String ecdsaCurveName) throws Exception {
		if (ecdsaCurveName == null || "".equals(ecdsaCurveName.trim())) {
			throw new Exception("Missing ECDSA curve name parameter");
		}
		final String curveName = ecdsaCurveName.replace("nist", "sec").toLowerCase().trim();
		if (!"sep256".equals(curveName) && !"secp384".equals(curveName) && !"secp521".equals(curveName)) {
			throw new Exception("Unknown ECDSA curve name: " + ecdsaCurveName);
		}
		this.comment = comment;
		final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(curveName + "r1"));
		final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
		keyPair = keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a PuTTY key with given keypair
	 */
	public PuttyKey(final String comment, final KeyPair keyPair) throws Exception {
		this.comment = comment;
		if (!keyPair.getPublic().getAlgorithm().equals("RSA")
				&& !keyPair.getPublic().getAlgorithm().equals("DSA")
				&& !keyPair.getPublic().getAlgorithm().equals("EC")) {
			throw new IllegalArgumentException("Unknown public key encoding: " + keyPair.getPublic().getAlgorithm());
		}
		this.keyPair = keyPair;
	}

	/**
	 * Create a PuTTY key with given keydata
	 */
	public PuttyKey(final String comment, final String algorithmName, final byte[] privateKeyBytes, final byte[] publicKeyBytes) throws Exception {
		this.comment = comment;
		final BlockDataReader publicKeyReader = new BlockDataReader(publicKeyBytes);
		final String cipherName = publicKeyReader.readString();
		if (cipherName == null || !cipherName.equalsIgnoreCase(algorithmName)) {
			throw new Exception("Corrupt public key data: Cipher name in data differs from defined cipher name. Expected \"" + algorithmName + "\", but was \"" + cipherName + "\"");
		}
		final BlockDataReader privateKeyReader = new BlockDataReader(privateKeyBytes);

		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(algorithmName)) {
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
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
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
		} else if (SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)
				|| SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)
				|| SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			final String curveName = publicKeyReader.readString();
			int qLength;
			if ("nistp256".equals(curveName)) {
				qLength = 65;
			} else if ("nistp384".equals(curveName)) {
				qLength = 97;
			} else if ("nistp521".equals(curveName)) {
				qLength = 133;
			} else {
				throw new Exception("Unsupported ECDSA curveName: " + curveName);
			}
			final int xLength = (qLength - 1) / 2;

			final BigInteger q = publicKeyReader.readBigInt();
			final byte[] x = new byte[xLength];
			final byte[] y = new byte[xLength];
			System.arraycopy(q.toByteArray(), 1, x, 0, xLength);
			System.arraycopy(q.toByteArray(), xLength + 1, y, 0, xLength);

			final KeyFactory keyFactory = KeyFactory.getInstance("EC");
			final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(curveName.replace("nist", "sec") + "r1"));
			final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

			final BigInteger p = privateKeyReader.readBigInt();

			final PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)), ecParameterSpec));
			final PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(p, ecParameterSpec));

			keyPair = new KeyPair(publicKey, privateKey);
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public String getAlgorithm() throws Exception {
		if (keyPair.getPublic().getAlgorithm().equals("RSA")){
			return SSH_CIPHER_NAME_RSA;
		} else if(keyPair.getPublic().getAlgorithm().equals("DSA")){
			return SSH_CIPHER_NAME_DSA;
		} else if(keyPair.getPublic().getAlgorithm().equals("EC")){
			final int bitLength = ((ECPublicKey) keyPair.getPublic()).getW().getAffineX().bitLength();
			if (bitLength <= 256) {
				return SSH_CIPHER_NAME_ECDSA_NISTP256;
			} else if (bitLength <= 384) {
				return SSH_CIPHER_NAME_ECDSA_NISTP384;
			} else if (bitLength <= 521) {
				return SSH_CIPHER_NAME_ECDSA_NISTP521;
			} else {
				throw new Exception("Unsupported ECDSA bit length: " + bitLength);
			}
		} else{
			throw new IllegalArgumentException("Unknown public key encoding: " + keyPair.getPublic().getAlgorithm());
		}
	}

	public int getKeyStrength() throws Exception {
		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(getAlgorithm())) {
			return ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength();
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(getAlgorithm())) {
			return 1024;
		} else if (SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(getAlgorithm())) {
			return 256;
		} else if (SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(getAlgorithm())) {
			return 384;
		} else if (SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(getAlgorithm())) {
			return 521;
		} else {
			throw new Exception("Unsupported cipher: " + getAlgorithm());
		}
	}

	public String getComment() {
		return comment;
	}

	public void setComment(final String comment) {
		this.comment = comment;
	}

	public String getMd5Fingerprint() throws Exception {
		try {
			final MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(getPublicKeyBytes());
			return toHexString(md.digest(), ":");
		} catch (final Exception e) {
			throw new Exception("Cannot create MD5 fingerprint", e);
		}
	}

	private static String toHexString(final byte[] data, final String separator) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			if (returnString.length() > 0) {
				returnString.append(separator);
			}
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString().toLowerCase();
	}

	public String getSha256Fingerprint() throws Exception {
		try {
			final MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(getPublicKeyBytes());
			return Base64.getEncoder().encodeToString(md.digest());
		} catch (final Exception e) {
			throw new Exception("Cannot create SHA256 fingerprint", e);
		}
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
		final BlockDataWriter publicKeyWriter = new BlockDataWriter();
		final String algorithmName = getAlgorithm();
		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			final RSAPublicKey publicKey = ((RSAPublicKey) keyPair.getPublic());
			publicKeyWriter.writeString(SSH_CIPHER_NAME_RSA);
			publicKeyWriter.writeBigInt(publicKey.getPublicExponent());
			publicKeyWriter.writeBigInt(publicKey.getModulus());
			return publicKeyWriter.toByteArray();
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			final DSAPublicKey publicKey = ((DSAPublicKey) keyPair.getPublic());
			publicKeyWriter.writeString(SSH_CIPHER_NAME_DSA);
			publicKeyWriter.writeBigInt(publicKey.getParams().getP());
			publicKeyWriter.writeBigInt(publicKey.getParams().getQ());
			publicKeyWriter.writeBigInt(publicKey.getParams().getG());
			publicKeyWriter.writeBigInt(publicKey.getY());
		} else if (SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)
				|| SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)
				|| SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			final ECPublicKey publicKey = ((ECPublicKey) keyPair.getPublic());
			final int bitLength = publicKey.getW().getAffineX().bitLength();
			String curveName = null;
			int qLength;
			if (bitLength <= 256) {
				curveName = "nistp256";
				qLength = 65;
			} else if (bitLength <= 384) {
				curveName = "nistp384";
				qLength = 97;
			} else if (bitLength <= 521) {
				curveName = "nistp521";
				qLength = 133;
			} else {
				throw new Exception("Unsupported ECDSA bit length: " + bitLength);
			}

			publicKeyWriter.writeString(algorithmName);
			publicKeyWriter.writeString(curveName);

			final byte[] javaEncoding = publicKey.getEncoded();
			final byte[] q = new byte[qLength];
			System.arraycopy(javaEncoding, javaEncoding.length - qLength, q, 0, qLength);
			publicKeyWriter.writeData(q);
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
		return publicKeyWriter.toByteArray();
	}

	public byte[] getPrivateKeyBytes() throws Exception {
		final BlockDataWriter privateKeyWriter = new BlockDataWriter();
		final String algorithmName = getAlgorithm();
		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) keyPair.getPrivate());
			privateKeyWriter.writeBigInt(privateKey.getPrivateExponent());
			privateKeyWriter.writeBigInt(privateKey.getPrimeP());
			privateKeyWriter.writeBigInt(privateKey.getPrimeQ());
			privateKeyWriter.writeBigInt(privateKey.getCrtCoefficient());
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			final DSAPrivateKey privateKey = ((DSAPrivateKey) keyPair.getPrivate());
			privateKeyWriter.writeBigInt(privateKey.getX());
		} else if (SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)
				|| SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)
				|| SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			final ECPrivateKey privateKey = ((ECPrivateKey) keyPair.getPrivate());
			privateKeyWriter.writeBigInt(privateKey.getS());
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
		return privateKeyWriter.toByteArray();
	}

	public String encodePublicKeyForAuthorizedKeys() throws Exception {
		return getAlgorithm() + " " + new String(Base64.getEncoder().encode(getPublicKeyBytes()));
	}

	public class BlockDataReader {
		private final DataInput keyDataInput;

		public BlockDataReader(final byte[] key) {
			keyDataInput = new DataInputStream(new ByteArrayInputStream(key));
		}

		public BigInteger readBigInt() throws Exception {
			return new BigInteger(readData());
		}

		public String readString() throws Exception {
			return new String(readData(), "ISO-8859-1");
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

	public class BlockDataWriter {
		private final ByteArrayOutputStream outputStream;
		private final DataOutput keyDataOutput;

		public BlockDataWriter() {
			outputStream = new ByteArrayOutputStream();
			keyDataOutput = new DataOutputStream(outputStream);
		}

		public void writeBigInt(final BigInteger bigIntegerData) throws Exception {
			writeData(bigIntegerData.toByteArray());
		}

		public void writeString(final String stringData) throws Exception {
			writeData(stringData.getBytes("ISO-8859-1"));
		}

		private void writeData(final byte[] data) throws IOException, Exception {
			try {
				if (data.length <= 0) {
					throw new Exception("Key blocksize error");
				}

				keyDataOutput.writeInt(data.length);
				keyDataOutput.write(data);
			} catch (final IOException e) {
				throw new Exception("Key block write error", e);
			}
		}

		public byte[] toByteArray() {
			return outputStream.toByteArray();
		}
	}
}
