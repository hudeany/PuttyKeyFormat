package de.soderer.utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Container for PuTTY key data
 */
public class PuttyKey {
	public static String SSH_CIPHER_NAME_RSA = "ssh-rsa";
	public static String SSH_CIPHER_NAME_DSA = "ssh-dss";

	private String comment;
	private final KeyPair keyPair;

	public PuttyKey(final String comment, final int keyStrength) throws Exception {
		this.comment = comment;
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keyStrength);
		keyPair = keyPairGenerator.generateKeyPair();
	}

	public PuttyKey(final String comment, final KeyPair keyPair) throws Exception {
		this.comment = comment;
		if (!keyPair.getPublic().getAlgorithm().equals("RSA") && !keyPair.getPublic().getAlgorithm().equals("DSA")) {
			throw new IllegalArgumentException("Unknown public key encoding: " + keyPair.getPublic().getAlgorithm());
		}
		this.keyPair = keyPair;
	}

	public PuttyKey(final String comment, final String algorithmName, final byte[] privateKeyBytes, final byte[] publicKeyBytes) throws Exception {
		this.comment = comment;
		final BlockDataReader publicKeyReader = new BlockDataReader(publicKeyBytes);
		final String cipherName = publicKeyReader.readString();
		if (cipherName == null || !cipherName.equalsIgnoreCase(algorithmName)) {
			throw new Exception("Corrupt public key data: Cipher name in data differs from defined cipher name. Expected \"" +  getAlgorithm()+ "\", but was \"" + cipherName + "\"");
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
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
	}

	/**
	 * Key type. Either "ssh-rsa" for RSA key, or "ssh-dss" for DSA key.
	 */
	public String getAlgorithm() {
		if (keyPair.getPublic().getAlgorithm().equals("RSA")){
			return SSH_CIPHER_NAME_RSA;
		} else if(keyPair.getPublic().getAlgorithm().equals("DSA")){
			return SSH_CIPHER_NAME_DSA;
		} else{
			throw new IllegalArgumentException("Unknown public key encoding: " + keyPair.getPublic().getAlgorithm());
		}
	}

	public int getKeyStrength() throws Exception {
		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(getAlgorithm())) {
			return ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength();
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(getAlgorithm())) {
			return 1024;
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

	private String toHexString(final byte[] data, final String separator) {
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
		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(getAlgorithm())) {
			final RSAPublicKey publicKey = ((RSAPublicKey) keyPair.getPublic());
			final BlockDataWriter publicKeyWriter = new BlockDataWriter();
			publicKeyWriter.writeString(SSH_CIPHER_NAME_RSA);
			publicKeyWriter.writeBigInt(publicKey.getPublicExponent());
			publicKeyWriter.writeBigInt(publicKey.getModulus());
			return publicKeyWriter.toByteArray();
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(getAlgorithm())) {
			final DSAPublicKey publicKey = ((DSAPublicKey) keyPair.getPublic());
			final BlockDataWriter publicKeyWriter = new BlockDataWriter();
			publicKeyWriter.writeString(SSH_CIPHER_NAME_DSA);
			publicKeyWriter.writeBigInt(publicKey.getParams().getP());
			publicKeyWriter.writeBigInt(publicKey.getParams().getQ());
			publicKeyWriter.writeBigInt(publicKey.getParams().getG());
			publicKeyWriter.writeBigInt(publicKey.getY());
			return publicKeyWriter.toByteArray();
			//		} else if () {
			//            ByteArrayOutputStream buf = new ByteArrayOutputStream();
			//
			//            int bitLength = key.getW().getAffineX().bitLength();
			//            String curveName = null;
			//            int qLen;
			//            if (bitLength <= 256) {
			//                curveName = "nistp256";
			//                qLen = 65;
			//            } else if (bitLength <= 384) {
			//                curveName = "nistp384";
			//                qLen = 97;
			//            } else if (bitLength <= 521) {
			//                curveName = "nistp521";
			//                qLen = 133;
			//            } else {
			//                throw new CryptoException("ECDSA bit length unsupported: " + bitLength);
			//            }
			//
			//            byte[] name = ("ecdsa-sha2-" + curveName).getBytes(StandardCharsets.US_ASCII);
			//            byte[] curve = curveName.getBytes(StandardCharsets.US_ASCII);
			//            writeArray(name, buf);
			//            writeArray(curve, buf);
			//
			//            byte[] javaEncoding = key.getEncoded();
			//            byte[] q = new byte[qLen];
			//
			//            System.arraycopy(javaEncoding, javaEncoding.length - qLen, q, 0, qLen);
			//            writeArray(q, buf);
			//
			//            return buf.toByteArray();
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + getAlgorithm());
		}
	}

	public byte[] getPrivateKeyBytes() throws Exception {
		if (SSH_CIPHER_NAME_RSA.equalsIgnoreCase(getAlgorithm())) {
			final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) keyPair.getPrivate());
			final BlockDataWriter privateKeyWriter = new BlockDataWriter();
			privateKeyWriter.writeBigInt(privateKey.getPrivateExponent());
			privateKeyWriter.writeBigInt(privateKey.getPrimeP());
			privateKeyWriter.writeBigInt(privateKey.getPrimeQ());
			privateKeyWriter.writeBigInt(privateKey.getCrtCoefficient());
			return privateKeyWriter.toByteArray();
		} else if (SSH_CIPHER_NAME_DSA.equalsIgnoreCase(getAlgorithm())) {
			final DSAPrivateKey privateKey = ((DSAPrivateKey) keyPair.getPrivate());
			final BlockDataWriter privateKeyWriter = new BlockDataWriter();
			privateKeyWriter.writeBigInt(privateKey.getX());
			return privateKeyWriter.toByteArray();
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + getAlgorithm());
		}
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
				if (nextBlockSize <= 0 || nextBlockSize > 513) {
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
				if (data.length <= 0 || data.length > 513) {
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
