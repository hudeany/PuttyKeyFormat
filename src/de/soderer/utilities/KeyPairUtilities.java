package de.soderer.utilities;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Base64;

public class KeyPairUtilities {
	public static String SSH_ALGORITHM_NAME_RSA = "ssh-rsa";
	public static String SSH_ALGORITHM_NAME_DSA = "ssh-dss";
	public static String SSH_ALGORITHM_NAME_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";
	public static String SSH_ALGORITHM_NAME_ECDSA_NISTP384 = "ecdsa-sha2-nistp384";
	public static String SSH_ALGORITHM_NAME_ECDSA_NISTP521 = "ecdsa-sha2-nistp521";

	/**
	 * Create a RSA keypair of given strength
	 */
	public static KeyPair createRsaKeyPair(final int keyStrength) throws Exception {
		if (keyStrength < 512) {
			throw new Exception("Invalid RSA key strength: " + keyStrength);
		}
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keyStrength);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a DSA keypair of 1024 bit strength<br/>
	 * Watchout: OpenSSH only supports 1024 bit DSA key strength<br/>
	 */
	public static KeyPair createDsaKeyPair() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(1024);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a DSA keypair of given strength<br/>
	 * Watchout: OpenSSH only supports 1024 bit DSA key strength<br/>
	 */
	public static KeyPair createDsaKeyPair(final int keyStrength) throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(keyStrength);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a ECDSA keypair of eliptic curve name.
	 * Supported eliptic curve names are
	 *   nistp256 or secp256
	 *   nistp384 or secp384
	 *   nistp521 or secp521
	 */
	public static KeyPair createEllipticCurveKeyPair(final String ecdsaCurveName) throws Exception {
		if (ecdsaCurveName == null || "".equals(ecdsaCurveName.trim())) {
			throw new Exception("Missing ECDSA curve name parameter");
		}
		final String curveName = ecdsaCurveName.replace("nist", "sec").toLowerCase().trim();
		if (!"secp256".equals(curveName) && !"secp384".equals(curveName) && !"secp521".equals(curveName)) {
			throw new Exception("Unknown ECDSA curve name: " + ecdsaCurveName);
		}
		final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(curveName + "r1"));
		final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
		return keyPairGenerator.generateKeyPair();
	}

	public static KeyPair createEllipticCurveKeyPair(final int curveId) throws Exception {
		if (256 != curveId && 384 != curveId && 521 != curveId) {
			throw new Exception("Invalid ECDSA curve id parameter");
		}
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(curveId);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public static String getAlgorithm(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else if (keyPair.getPublic() != null) {
			return getAlgorithm(keyPair.getPublic());
		} else if (keyPair.getPrivate() != null) {
			return getAlgorithm(keyPair.getPrivate());
		} else {
			throw new Exception("KeyPair data is empty");
		}
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public static String getAlgorithm(final PublicKey publicKey) throws Exception {
		if (publicKey == null){
			throw new Exception("Invalid empty publicKey parameter");
		} else if (publicKey.getAlgorithm().equals("RSA")){
			return SSH_ALGORITHM_NAME_RSA;
		} else if(publicKey.getAlgorithm().equals("DSA")){
			return SSH_ALGORITHM_NAME_DSA;
		} else if(publicKey.getAlgorithm().equals("EC") || publicKey.getAlgorithm().equals("ECDSA")){
			final int bitLength = ((ECPublicKey) publicKey).getW().getAffineX().bitLength();
			if (bitLength <= 256) {
				return SSH_ALGORITHM_NAME_ECDSA_NISTP256;
			} else if (bitLength <= 384) {
				return SSH_ALGORITHM_NAME_ECDSA_NISTP384;
			} else if (bitLength <= 521) {
				return SSH_ALGORITHM_NAME_ECDSA_NISTP521;
			} else {
				throw new Exception("Unsupported ECDSA bit length: " + bitLength);
			}
		} else {
			throw new Exception("Unsupported ssh algorithm name: " + publicKey.getAlgorithm());
		}
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public static String getAlgorithm(final PrivateKey privateKey) throws Exception {
		if (privateKey == null){
			throw new Exception("Invalid empty privateKey parameter");
		} else if (privateKey instanceof RSAPrivateCrtKey) {
			return KeyPairUtilities.SSH_ALGORITHM_NAME_RSA;
		} else if (privateKey instanceof DSAPrivateKey) {
			return KeyPairUtilities.SSH_ALGORITHM_NAME_DSA;
		} else if (privateKey instanceof ECPrivateKey) {
			final int bitLength = ((ECPrivateKey) privateKey).getS().bitLength();
			if (bitLength <= 256) {
				return KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP256;
			} else if (bitLength <= 384) {
				return KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP384;
			} else if (bitLength <= 521) {
				return KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP521;
			} else {
				throw new Exception("Unsupported ECDSA bit length: " + bitLength);
			}
		} else{
			throw new IllegalArgumentException("Unknown private key cipher");
		}
	}

	public static int getKeyStrength(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getKeyStrength(keyPair.getPublic());
		}
	}

	public static int getKeyStrength(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			final String algorithmName = getAlgorithm(publicKey);
			if (SSH_ALGORITHM_NAME_RSA.equalsIgnoreCase(algorithmName)) {
				return ((RSAPublicKey) publicKey).getModulus().bitLength();
			} else if (SSH_ALGORITHM_NAME_DSA.equalsIgnoreCase(algorithmName)) {
				return ((DSAPublicKey) publicKey).getY().bitLength();
			} else if (SSH_ALGORITHM_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
				return 256;
			} else if (SSH_ALGORITHM_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
				return 384;
			} else if (SSH_ALGORITHM_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
				return 521;
			} else {
				throw new Exception("Unsupported ssh algorithm name: " + algorithmName);
			}
		}
	}

	public static byte[] getPublicKeyBytes(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getPublicKeyBytes(keyPair.getPublic());
		}
	}

	public static byte[] getPublicKeyBytes(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			final BlockDataWriter publicKeyWriter = new BlockDataWriter();
			final String algorithmName = getAlgorithm(publicKey);
			if (publicKey instanceof RSAPublicKey) {
				final RSAPublicKey publicKeyRSA = (RSAPublicKey) publicKey;
				publicKeyWriter.writeString(SSH_ALGORITHM_NAME_RSA);
				publicKeyWriter.writeBigInt(publicKeyRSA.getPublicExponent());
				publicKeyWriter.writeBigInt(publicKeyRSA.getModulus());
				return publicKeyWriter.toByteArray();
			} else if (publicKey instanceof DSAPublicKey) {
				final DSAPublicKey publicKeyDSA = (DSAPublicKey) publicKey;
				publicKeyWriter.writeString(SSH_ALGORITHM_NAME_DSA);
				publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getP());
				publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getQ());
				publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getG());
				publicKeyWriter.writeBigInt(publicKeyDSA.getY());
			} else if (publicKey instanceof ECPublicKey) {
				final ECPublicKey publicKeyEC = (ECPublicKey) publicKey;
				final int bitLength = publicKeyEC.getW().getAffineX().bitLength();
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
				final byte[] javaEncoding = publicKeyEC.getEncoded();
				final byte[] q = new byte[qLength];
				System.arraycopy(javaEncoding, javaEncoding.length - qLength, q, 0, qLength);
				publicKeyWriter.writeData(q);
			} else {
				throw new Exception("Unsupported ssh algorithm name: " + algorithmName);
			}
			return publicKeyWriter.toByteArray();
		}
	}

	public static byte[] getPrivateKeyBytes(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getPrivateKeyBytes(keyPair.getPrivate());
		}
	}

	public static byte[] getPrivateKeyBytes(final PrivateKey privateKey) throws Exception {
		if (privateKey == null) {
			throw new Exception("Invalid empty privateKey parameter");
		} else {
			final BlockDataWriter privateKeyWriter = new BlockDataWriter();
			if (privateKey instanceof RSAPrivateCrtKey) {
				final RSAPrivateCrtKey privateKeyRSA = (RSAPrivateCrtKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrivateExponent());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeP());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeQ());
				privateKeyWriter.writeBigInt(privateKeyRSA.getCrtCoefficient());
			} else if (privateKey instanceof DSAPrivateKey) {
				final DSAPrivateKey privateKeyDSA = (DSAPrivateKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyDSA.getX());
			} else if (privateKey instanceof ECPrivateKey) {
				final ECPrivateKey privateKeyEC = (ECPrivateKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyEC.getS());
			} else {
				throw new IllegalArgumentException("Unsupported ssh algorithm");
			}
			return privateKeyWriter.toByteArray();
		}
	}

	public static String getMd5Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getMd5Fingerprint(keyPair.getPublic());
		}
	}

	public static String getMd5Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(getPublicKeyBytes(publicKey));
				return toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create MD5 fingerprint", e);
			}
		}
	}

	public static String getSha1Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha1Fingerprint(keyPair.getPublic());
		}
	}

	public static String getSha1Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(getPublicKeyBytes(publicKey));
				return toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA256 fingerprint", e);
			}
		}
	}

	public static String getSha1FingerprintBase64(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha1FingerprintBase64(keyPair.getPublic());
		}
	}

	public static String getSha1FingerprintBase64(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(getPublicKeyBytes(publicKey));
				return Base64.getEncoder().encodeToString(md.digest());
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA256 fingerprint", e);
			}
		}
	}

	public static String getSha256Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha256Fingerprint(keyPair.getPublic());
		}
	}

	public static String getSha256Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(getPublicKeyBytes(publicKey));
				return toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA256 fingerprint", e);
			}
		}
	}

	public static String getSha256FingerprintBase64(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha256FingerprintBase64(keyPair.getPublic());
		}
	}

	public static String getSha256FingerprintBase64(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(getPublicKeyBytes(publicKey));
				return Base64.getEncoder().encodeToString(md.digest());
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA256 fingerprint", e);
			}
		}
	}

	public static String encodePublicKeyForAuthorizedKeys(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return encodePublicKeyForAuthorizedKeys(keyPair.getPublic());
		}
	}

	public static String encodePublicKeyForAuthorizedKeys(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			return getAlgorithm(publicKey) + " " + new String(Base64.getEncoder().encode(getPublicKeyBytes(publicKey)));
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

	private static class BlockDataWriter {
		private final ByteArrayOutputStream outputStream;
		private final DataOutput keyDataOutput;

		private BlockDataWriter() {
			outputStream = new ByteArrayOutputStream();
			keyDataOutput = new DataOutputStream(outputStream);
		}

		private void writeBigInt(final BigInteger bigIntegerData) throws Exception {
			writeData(bigIntegerData.toByteArray());
		}

		private void writeString(final String stringData) throws Exception {
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

		private byte[] toByteArray() {
			return outputStream.toByteArray();
		}
	}
}
