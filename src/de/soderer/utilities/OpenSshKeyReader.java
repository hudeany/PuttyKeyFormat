package de.soderer.utilities;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.soderer.utilities.Asn1Codec.DerTag;

public class OpenSshKeyReader implements Closeable {
	private static final String AES128_PemEncryptionMethodName = "AES-128-CBC";
	private static final String TripleDES_PemEncryptionMethodName = "DES-EDE3-CBC";

	private final BufferedReader dataReader;

	public OpenSshKeyReader(final InputStream inputStream) throws IOException {
		dataReader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
	}

	public KeyPair readKey(final char[] password) throws Exception {
		KeyPair keyPair = new KeyPair(null, null);

		String currentKeyName = null;
		Map<String, String> currentKeyHeaders = null;
		StringBuilder currentKeyData = null;
		String nextLine;
		boolean withinKeyData = false;
		while ((nextLine = dataReader.readLine()) != null) {
			if (nextLine.startsWith("-----BEGIN ") && nextLine.endsWith("-----")) {
				if (withinKeyData) {
					throw new Exception("Invalid keydata found");
				}
				withinKeyData = true;
				currentKeyName = nextLine.substring(11, nextLine.length() - 5);
				currentKeyHeaders = new HashMap<>();
				currentKeyData = new StringBuilder();
			} else if (nextLine.equals("---- BEGIN SSH2 PUBLIC KEY ----")) {
				if (withinKeyData) {
					throw new Exception("Invalid keydata found");
				}
				withinKeyData = true;
				currentKeyName = "SSH2 PUBLIC KEY";
				currentKeyHeaders = new HashMap<>();
				currentKeyData = new StringBuilder();
			} else if (nextLine.equals("---- BEGIN SSH2 PRIVATE KEY ----")) {
				if (withinKeyData) {
					throw new Exception("Invalid keydata found");
				}
				withinKeyData = true;
				currentKeyName = "SSH2 PRIVATE KEY";
				currentKeyHeaders = new HashMap<>();
				currentKeyData = new StringBuilder();
			} else if ((nextLine.startsWith("-----END ") && nextLine.endsWith("-----")) || (nextLine.startsWith("---- END ") && nextLine.endsWith(" ----"))) {
				if (!withinKeyData) {
					throw new Exception("Invalid keydata found");
				}
				withinKeyData = false;
				final String endKeyName = nextLine.substring(9, nextLine.length() - 5);
				if (currentKeyName == null || !currentKeyName.equals(endKeyName)) {
					throw new Exception("Corrupt key data found");
				} else {
					byte[] keyData = Base64.getDecoder().decode(currentKeyData.toString());
					if ("4,ENCRYPTED".equals(currentKeyHeaders.get("Proc-Type"))) {
						if (password == null) {
							throw new WrongPasswordException();
						}
						final String dekInfo = currentKeyHeaders.get("DEK-Info");
						if (dekInfo == null) {
							throw new Exception("Missing key encryption info (DEK-Info)");
						}
						final String[] dekInfoParts = dekInfo.split(",");
						if (dekInfoParts.length < 2) {
							throw new Exception("Invalid key encryption info (DEK-Info)");
						}
						final String keyEncryptionCipherName = dekInfoParts[0].trim();
						final String ivString = dekInfoParts[1].trim();
						if (TripleDES_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
							final byte[] iv = fromHexString(ivString);
							final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
							cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(stretchPasswordForOpenSsl(password, iv, 8, 24), "DESede"), new IvParameterSpec(iv));
							keyData = cipher.doFinal(keyData);
						} else if (AES128_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
							final byte[] iv = fromHexString(ivString);
							final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
							cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(stretchPasswordForOpenSsl(password, iv, 8, 16), "AES"), new IvParameterSpec(iv));
							keyData = cipher.doFinal(keyData);
						} else {
							throw new Exception("Unknown key encryption cipher: " + keyEncryptionCipherName);
						}
					}

					if (currentKeyName.toLowerCase().contains("private")) {
						if (keyPair.getPrivate() != null) {
							throw new Exception("Multiple private key data found");
						} else {
							keyPair = readPrivateKey(keyPair, currentKeyName, currentKeyHeaders, keyData);
						}
					} else if (currentKeyName.toLowerCase().contains("public")) {
						if (keyPair.getPublic() != null) {
							// keep the first found public key, but check if the new public key fits the old one
							// TODO
						} else {
							keyPair = readPkcs1PublicKey(keyPair, currentKeyName, currentKeyHeaders, keyData);
						}
					} else {
						throw new Exception("Unknown key identifier found");
					}
					currentKeyName = null;
				}
			} else if (currentKeyName != null) {
				final int indexOfHeaderSeparator = nextLine.indexOf(": ");
				if (indexOfHeaderSeparator > 0) {
					if (currentKeyData.length() > 0) {
						throw new Exception("Corrupt key data found");
					}
					final String headerName = nextLine.substring(0, indexOfHeaderSeparator).trim();
					currentKeyHeaders.put(headerName, nextLine.substring(indexOfHeaderSeparator + 2));
				} else {
					currentKeyData.append(nextLine);
				}
			}
		}

		if (keyPair.getPublic() == null && keyPair.getPrivate() == null) {
			throw new Exception("No keydata found");
		} else {
			return keyPair;
		}
	}

	private KeyPair readPkcs1PublicKey(final KeyPair keyPair, final String keyName, final Map<String, String> keyHeaders, final byte[] data) throws Exception {
		if (keyName == null || "".equals(keyName.trim())) {
			throw new Exception("Invalid empty key name");
		} else {
			final BlockDataReader publicKeyReader = new BlockDataReader(data);
			final String algorithmName = publicKeyReader.readString();
			if (KeyPairUtilities.SSH_ALGORITHM_NAME_RSA.equalsIgnoreCase(algorithmName)) {
				final BigInteger publicExponent = publicKeyReader.readBigInt();
				final BigInteger modulus = publicKeyReader.readBigInt();

				final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				final PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

				return new KeyPair(publicKey, keyPair.getPrivate());
			} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_DSA.equalsIgnoreCase(algorithmName)) {
				final BigInteger p = publicKeyReader.readBigInt();
				final BigInteger q = publicKeyReader.readBigInt();
				final BigInteger g = publicKeyReader.readBigInt();

				final BigInteger y = publicKeyReader.readBigInt();

				final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
				final PublicKey publicKey = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));

				return new KeyPair(publicKey, keyPair.getPrivate());
			} else if (KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)
					|| KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)
					|| KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
				final String curveName = publicKeyReader.readString();
				if ("nistp256".equals(curveName)) {
				} else if ("nistp384".equals(curveName)) {
				} else if ("nistp521".equals(curveName)) {
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

				final PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)), ecParameterSpec));

				return new KeyPair(publicKey, keyPair.getPrivate());
			} else {
				throw new IllegalArgumentException("Invalid public key algorithm for PuTTY key (only supports RSA / DSA / EC): " + algorithmName);
			}
		}
		//		else {
		//			throw new IllegalArgumentException("Unsupported key name: " + keyName);
		//		}
	}

	private KeyPair readPrivateKey(final KeyPair keyPair, final String keyName, final Map<String, String> keyHeaders, final byte[] data) throws Exception {
		if (keyName == null || "".equals(keyName.trim())) {
			throw new Exception("Invalid empty key name");
		} else if (keyName.equals("SSH2 PRIVATE KEY")) {
			return readPkcs1PrivateKey(keyPair, data);
		} else if (keyName.startsWith("RSA")) {
			return readRsaPrivateKey(data);
		} else if (keyName.startsWith("DSA")) {
			return readDsaPrivateKey(data);
		} else if (keyName.startsWith("EC")) {
			return readEcdsaPrivateKey(data);
		} else {
			throw new IllegalArgumentException("Unsupported key name: " + keyName);
		}
	}

	private KeyPair readPkcs1PrivateKey(final KeyPair keyPair, final byte[] data) throws Exception {
		//		final BlockDataReader privateKeyReader = new BlockDataReader(data);
		//		final BigInteger test1 = privateKeyReader.readBigInt();
		//		final BigInteger test2 = privateKeyReader.readBigInt();
		//		final BigInteger test3 = privateKeyReader.readBigInt();
		//		final BigInteger test4 = privateKeyReader.readBigInt();
		//		final BigInteger test5 = privateKeyReader.readBigInt();
		//		//TODO detect key type
		//		xxx
		return new KeyPair(keyPair.getPublic(), keyPair.getPrivate());
	}

	private KeyPair readRsaPrivateKey(final byte[] data) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(data);
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());

		final BigInteger keyEncodingVersion = new BigInteger(derDataTags.get(0).getData());
		if (!BigInteger.ZERO.equals(keyEncodingVersion)) {
			throw new Exception("Invalid key data version found");
		}

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(1).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger modulus = new BigInteger(derDataTags.get(1).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(2).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger publicExponent = new BigInteger(derDataTags.get(2).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(3).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger privateExponent = new BigInteger(derDataTags.get(3).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(4).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger primeP = new BigInteger(derDataTags.get(4).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(5).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger primeQ = new BigInteger(derDataTags.get(5).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(6).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger primeExponentP = new BigInteger(derDataTags.get(6).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(7).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger primeExponentQ = new BigInteger(derDataTags.get(7).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(8).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger crtCoefficient = new BigInteger(derDataTags.get(8).getData());

		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		final PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		final PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient));
		return new KeyPair(publicKey, privateKey);
	}

	private KeyPair readDsaPrivateKey(final byte[] data) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(data);
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());

		final BigInteger keyEncodingVersion = new BigInteger(derDataTags.get(0).getData());
		if (!BigInteger.ZERO.equals(keyEncodingVersion)) {
			throw new Exception("Invalid key data version found");
		}

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(1).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger p = new BigInteger(derDataTags.get(1).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(2).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger q = new BigInteger(derDataTags.get(2).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(3).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger g = new BigInteger(derDataTags.get(3).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(4).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger y = new BigInteger(derDataTags.get(4).getData());

		if (Asn1Codec.DER_TAG_INTEGER != derDataTags.get(5).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final BigInteger x = new BigInteger(derDataTags.get(5).getData());

		final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		final PublicKey publicKey = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
		final PrivateKey privateKey = keyFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
		return new KeyPair(publicKey, privateKey);
	}

	private KeyPair readEcdsaPrivateKey(final byte[] data) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(data);
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());

		final BigInteger keyEncodingVersion = new BigInteger(derDataTags.get(0).getData());
		if (!BigInteger.ONE.equals(keyEncodingVersion)) {
			throw new Exception("Invalid key data version found");
		}

		if (Asn1Codec.DER_TAG_OCTET_STRING != derDataTags.get(1).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final byte[] sBytes = derDataTags.get(1).getData();

		if (Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_0 != derDataTags.get(2).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final byte[] oidTagBytes = derDataTags.get(2).getData();
		final DerTag oidTag = Asn1Codec.readDerTag(oidTagBytes);
		if (Asn1Codec.DER_TAG_OBJECT != oidTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final byte[] oidBytes = oidTag.getData();
		String curveName;
		if (Arrays.equals(OID.SECP256R1_ARRAY, oidBytes)) {
			curveName = "nistp256";
		} else if (Arrays.equals(OID.SECP384R1_ARRAY, oidBytes)) {
			curveName = "nistp384";
		} else if (Arrays.equals(OID.SECP521R1_ARRAY, oidBytes)) {
			curveName = "nistp521";
		} else {
			try {
				throw new Exception("Unsupported ec curve oid found: " + new OID(oidBytes).getStringEncoding());
			} catch (final Exception e) {
				throw new Exception("Invalid ec curve oid found");
			}
		}

		if (Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_1 != derDataTags.get(3).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final byte[] publicKeyTagBytes = derDataTags.get(3).getData();
		final DerTag publicKeyTag = Asn1Codec.readDerTag(publicKeyTagBytes);
		if (Asn1Codec.DER_TAG_BIT_STRING != publicKeyTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final byte[] qBytes = publicKeyTag.getData();
		if (0 != qBytes[0] || 4 != qBytes[1]) {
			throw new Exception("Invalid key data found");
		}
		final int xLength = (qBytes.length - 2) / 2;
		final byte[] xBytes = new byte[xLength];
		final byte[] yBytes = new byte[xLength];
		System.arraycopy(qBytes, 2, xBytes, 0, xLength);
		System.arraycopy(qBytes, xLength + 2, yBytes, 0, yBytes.length);

		final KeyFactory keyFactory = KeyFactory.getInstance("EC");
		final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(curveName.replace("nist", "sec") + "r1"));
		final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

		final PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(xBytes), new BigInteger(yBytes)), ecParameterSpec));
		final PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(new BigInteger(sBytes), ecParameterSpec));
		return new KeyPair(publicKey, privateKey);
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

	private static byte[] toBytes(final char[] chars, final String encoding) {
		final ByteBuffer byteBuffer = Charset.forName(encoding).encode(CharBuffer.wrap(chars));
		final byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}

	private static byte[] fromHexString(final String value) {
		final int length = value.length();
		final byte[] data = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(value.charAt(i), 16) << 4) + Character.digit(value.charAt(i + 1), 16));
		}
		return data;
	}

	@Override
	public void close() throws IOException {
		try {
			dataReader.close();
		} catch (final Exception e) {
			e.printStackTrace();
		}
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
}