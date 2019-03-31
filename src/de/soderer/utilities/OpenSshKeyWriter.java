package de.soderer.utilities;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OpenSshKeyWriter implements Closeable {
	private static final String AES128_PemEncryptionMethodName = "AES-128-CBC";
	private static final String TripleDES_PemEncryptionMethodName = "DES-EDE3-CBC";

	private final OutputStream outputStream;

	public OpenSshKeyWriter(final OutputStream outputStream) throws IOException {
		this.outputStream = outputStream;
	}

	/**
	 * Converts this public key into unprotected PEM format (PKCS#1) for OpenSSH keys<br />
	 * This format includes public key data only and is NOT accepted by PuTTY's key import<br />
	 */
	public void writePKCS1Format(final PublicKey publicKey) throws Exception {
		final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(publicKey);

		final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, 64, "\r\n");

		final StringBuilder content = new StringBuilder();
		content.append("---- BEGIN SSH2 PUBLIC KEY ----").append("\r\n");
		content.append(publicKeyBase64).append("\r\n");
		content.append("---- END SSH2 PUBLIC KEY ----").append("\r\n");

		outputStream.write(content.toString().getBytes("UTF-8"));
	}

	/**
	 * Converts this key into unprotected PEM format (PKCS#8) for OpenSSH keys<br />
	 * Using default encryption method "AES-128-CBC"<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import<br />
	 */
	public void writePKCS8Format(final KeyPair keyPair, final char[] password) throws Exception {
		writePKCS8Format(keyPair, null, password);
	}

	/**
	 * Converts this keypair into protected PEM format (PKCS#8) for OpenSSH keys<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import<br />
	 * <br />
	 * keyEncryptionCipherName:<br />
	 *   default is "AES-128-CBC"<br />
	 *   other value may be "DES-EDE3-CBC"<br />
	 */
	public void writePKCS8Format(final KeyPair keyPair, String keyEncryptionCipherName, final char[] password) throws Exception {
		String keyTypeName;
		byte[] keyData;
		final String algorithmName = KeyPairUtilities.getAlgorithm(keyPair);
		if (KeyPairUtilities.SSH_ALGORITHM_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "RSA PRIVATE KEY";
			keyData = createRsaBinaryKey(keyPair);
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "DSA PRIVATE KEY";
			keyData = createDssBinaryKey(keyPair);
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(keyPair, OID.SECP256R1_ARRAY);
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(keyPair, OID.SECP384R1_ARRAY);
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(keyPair, OID.SECP521R1_ARRAY);
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}

		final Map<String, String> headers = new LinkedHashMap<>();

		if (password != null && password.length > 0) {
			if (keyEncryptionCipherName == null || "".equals(keyEncryptionCipherName.trim())) {
				keyEncryptionCipherName = AES128_PemEncryptionMethodName;
			}

			if (!AES128_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName) && !TripleDES_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
				throw new Exception("Unknown key encryption cipher: " + keyEncryptionCipherName);
			}

			final SecureRandom rnd = new SecureRandom();
			final Cipher cipher;
			final String ivString;
			if (TripleDES_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
				final byte[] iv = new byte[8];
				rnd.nextBytes(iv);
				ivString = toHexString(iv);
				cipher = Cipher.getInstance("DESede/CBC/NoPadding");
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(stretchPasswordForOpenSsl(password, iv, 8, 24), "DESede"), new IvParameterSpec(iv));
				keyData = addLengthCodedPadding(keyData, 8);
			} else if (AES128_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
				final byte[] iv = new byte[16];
				rnd.nextBytes(iv);
				ivString = toHexString(iv);
				cipher = Cipher.getInstance("AES/CBC/NoPadding");
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(stretchPasswordForOpenSsl(password, iv, 8, 16), "AES"), new IvParameterSpec(iv));
				keyData = addLengthCodedPadding(keyData, 16);
			} else {
				throw new Exception("Unknown key encryption cipher: " + keyEncryptionCipherName);
			}
			headers.put("Proc-Type", "4,ENCRYPTED");
			headers.put("DEK-Info", keyEncryptionCipherName.toUpperCase() + "," + ivString);

			keyData = cipher.doFinal(keyData);
		}

		outputStream.write(("-----BEGIN " + keyTypeName + "-----\n").getBytes("UTF-8"));
		outputStream.write(getPemHeaderLines(headers, 64).getBytes("UTF-8"));
		outputStream.write(toWrappedBase64(keyData, 64, "\n").getBytes("UTF-8"));
		outputStream.write(("\n-----END " + keyTypeName + "-----\n").getBytes("UTF-8"));
	}

	/**
	 * Converts this key into unprotected DER format (binary data) for OpenSSH keys<br />
	 * <br />
	 * <b>Use with caution, because this key format is not protected by any password</>
	 */
	public void writeDerFormat(final KeyPair keyPair) throws Exception {
		final String algorithmName = KeyPairUtilities.getAlgorithm(keyPair);
		if (KeyPairUtilities.SSH_ALGORITHM_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createRsaBinaryKey(keyPair));
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createDssBinaryKey(keyPair));
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(keyPair, OID.SECP256R1_ARRAY));
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(keyPair, OID.SECP384R1_ARRAY));
		} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(keyPair, OID.SECP521R1_ARRAY));
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
	}

	private static String getPemHeaderLines(final Map<String, String> headers, final int maxLineLimit) {
		final StringBuilder headerBuilder = new StringBuilder();
		if (headers != null && !headers.isEmpty()) {
			for (final Entry<String, String> entry : headers.entrySet()) {
				headerBuilder.append(entry.getKey() + ": ");
				if ((entry.getKey().length() + entry.getValue().length() + 2) > maxLineLimit) {
					int offset = Math.max(maxLineLimit - entry.getKey().length() - 2, 0);
					headerBuilder.append(entry.getValue().substring(0, offset) + "\\" + "\n");
					for (; offset < entry.getValue().length(); offset += maxLineLimit) {
						if ((offset + maxLineLimit) >= entry.getValue().length()) {
							headerBuilder.append(entry.getValue().substring(offset) + "\n");
						} else {
							headerBuilder.append(entry.getValue().substring(offset, offset + maxLineLimit) + "\\" + "\n");
						}
					}
				} else {
					headerBuilder.append(entry.getValue() + "\n");
				}
			}

			headerBuilder.append("\n");
		}
		return headerBuilder.toString();
	}

	private static byte[] stretchPasswordForOpenSsl(final char[] password, final byte[] iv, final int usingIvSize, final int keySize) throws Exception {
		final byte[] passphraseBytes = toBytes(password, "ISO-8859-1");
		final MessageDigest hash = MessageDigest.getInstance("MD5");
		final byte[] key = new byte[keySize];
		int hashesSize = keySize & 0XFFFFFFF0;

		if ((keySize & 0XF) != 0) {
			hashesSize += 0x10;
		}

		final byte[] hashes = new byte[hashesSize];
		byte[] previous;
		for (int index = 0; (index + 0x10) <= hashes.length; hash.update(previous, 0, previous.length)) {
			hash.update(passphraseBytes, 0, passphraseBytes.length);
			hash.update(iv, 0, usingIvSize);
			previous = hash.digest();
			System.arraycopy(previous, 0, hashes, index, previous.length);
			index += previous.length;
		}

		System.arraycopy(hashes, 0, key, 0, key.length);
		return key;
	}

	private static byte[] createRsaBinaryKey(final KeyPair keyPair) throws Exception {
		final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) keyPair.getPrivate());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getModulus().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPublicExponent().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrivateExponent().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeExponentP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeExponentQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getCrtCoefficient().toByteArray())
				);
	}

	private static byte[] createDssBinaryKey(final KeyPair keyPair) throws Exception {
		final DSAPublicKey publicKey = ((DSAPublicKey) keyPair.getPublic());
		final DSAPrivateKey privateKey = ((DSAPrivateKey) keyPair.getPrivate());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getG().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, publicKey.getY().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getX().toByteArray())
				);
	}

	private static byte[] createEcdsaBinaryKey(final KeyPair keyPair, final byte[] oidKey) throws Exception {
		int qLength;
		if (Arrays.equals(OID.SECP256R1_ARRAY, oidKey)) {
			qLength = 66;
		} else if (Arrays.equals(OID.SECP384R1_ARRAY, oidKey)) {
			qLength = 98;
		} else if (Arrays.equals(OID.SECP521R1_ARRAY, oidKey)) {
			qLength = 134;
		} else {
			throw new Exception("Unsupported ECDSA curve");
		}

		final ECPrivateKey privateKey = ((ECPrivateKey) keyPair.getPrivate());
		final ECPublicKey publicKey = ((ECPublicKey) keyPair.getPublic());

		final byte[] javaEncoding = publicKey.getEncoded();
		final byte[] qBytes = new byte[qLength];

		System.arraycopy(javaEncoding, javaEncoding.length - qLength, qBytes, 0, qLength);

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ONE.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OCTET_STRING, privateKey.getS().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_0, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OBJECT, oidKey)),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_1, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_BIT_STRING, qBytes))
				);
	}

	private static byte[] addLengthCodedPadding(final byte[] data, final int paddingSize) {
		final byte[] dataPadded;
		if (data.length % paddingSize != 0) {
			dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
		} else {
			dataPadded = new byte[data.length + paddingSize];
		}
		for (int i = 0; i < data.length; i++) {
			dataPadded[i] = data[i];
		}
		final byte padValue = (byte) (dataPadded.length - data.length);
		for (int i = data.length; i < dataPadded.length; i++) {
			dataPadded[i] = padValue;
		}
		return dataPadded;
	}

	/**
	 * Converts byte array to base64 with linebreaks
	 */
	private static String toWrappedBase64(final byte[] byteArray, final int maxLineLength, final String lineBreak) {
		return Base64.getMimeEncoder(maxLineLength, lineBreak.getBytes(Charset.forName("UTF-8"))).encodeToString(byteArray);
	}

	private static String toHexString(final byte[] data) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString();
	}

	private static byte[] toBytes(final char[] chars, final String encoding) {
		final ByteBuffer byteBuffer = Charset.forName(encoding).encode(CharBuffer.wrap(chars));
		final byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}

	@Override
	public void close() {
		try {
			outputStream.close();
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
