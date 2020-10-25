package de.soderer.utilities.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;

import de.soderer.utilities.KeyPairUtilities;
import de.soderer.utilities.OpenSshKeyReader;
import de.soderer.utilities.OpenSshKeyWriter;

public class OpenSshKeyTest {
	public static void main(final String[] args) {
		try {
			testRsa();
			testDsa();
			testEc256();
			testSimpleEc256();
			testEc384();
			testSimpleEc384();
			testEc521();
			testSimpleEc521();

			System.out.println("Test passed successfully");
		} catch (final Exception e) {
			System.out.println("Test failed: " + e.getMessage());
		}
	}

	public static void testRsa() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);
		testKeyPair(keyPair);
	}

	public static void testDsa() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createDsaKeyPair(1024);
		testKeyPair(keyPair);
	}

	public static void testEc256() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");
		testKeyPair(keyPair);
	}

	public static void testSimpleEc256() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		testKeyPair(keyPair);
	}

	public static void testEc384() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");
		testKeyPair(keyPair);
	}

	public static void testSimpleEc384() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(384);
		testKeyPair(keyPair);
	}

	public static void testEc521() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp521");
		testKeyPair(keyPair);
	}

	public static void testSimpleEc521() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(521);
		testKeyPair(keyPair);
	}

	private static void testKeyPair(final KeyPair keyPair) throws Exception {
		final String sha256Fingerprint = KeyPairUtilities.getSha256Fingerprint(keyPair);

		final byte[] privateKeyPkcs8Data;
		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (OpenSshKeyWriter writer = new OpenSshKeyWriter(byteArrayOutStream)) {
				writer.writePKCS8Format(keyPair, "password".toCharArray());
			}
			byteArrayOutStream.flush();
			privateKeyPkcs8Data = byteArrayOutStream.toByteArray();
		}

		if (!new String(privateKeyPkcs8Data, "UTF-8").contains("----BEGIN ")) {
			throw new Exception();
		}

		KeyPair readKeyPair;
		try (OpenSshKeyReader reader = new OpenSshKeyReader(new ByteArrayInputStream(privateKeyPkcs8Data))) {
			readKeyPair = reader.readKey("password".toCharArray());
		}
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(KeyPairUtilities.getSha256Fingerprint(readKeyPair).toUpperCase().replace(":", ""))) {
			throw new Exception();
		}

		final byte[] publicKeyPkcs1Data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (OpenSshKeyWriter writer = new OpenSshKeyWriter(byteArrayOutStream)) {
				writer.writePKCS1Format(keyPair.getPublic());
			}
			byteArrayOutStream.flush();
			publicKeyPkcs1Data = byteArrayOutStream.toByteArray();
		}

		if (!new String(publicKeyPkcs1Data, "UTF-8").contains("---- BEGIN SSH2 PUBLIC KEY ----")) {
			throw new Exception();
		}
		KeyPair readKeyPair2;
		try (OpenSshKeyReader reader = new OpenSshKeyReader(new ByteArrayInputStream(publicKeyPkcs1Data))) {
			readKeyPair2 = reader.readKey("password".toCharArray());
		}
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(KeyPairUtilities.getSha256Fingerprint(readKeyPair2).toUpperCase().replace(":", ""))) {
			throw new Exception();
		}

		final byte[] keypairPkcs1Data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (OpenSshKeyWriter writer = new OpenSshKeyWriter(byteArrayOutStream)) {
				writer.writePKCS8Format(keyPair, null);
				writer.writePKCS1Format(keyPair.getPublic());
			}
			byteArrayOutStream.flush();
			keypairPkcs1Data = byteArrayOutStream.toByteArray();
		}

		if (!new String(keypairPkcs1Data, "UTF-8").contains("---- BEGIN SSH2 PUBLIC KEY ----")) {
			throw new Exception();
		}
		KeyPair readKeyPair3;
		try (OpenSshKeyReader reader = new OpenSshKeyReader(new ByteArrayInputStream(keypairPkcs1Data))) {
			readKeyPair3 = reader.readKey("password".toCharArray());
		}
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(KeyPairUtilities.getSha256Fingerprint(readKeyPair3).toUpperCase().replace(":", ""))) {
			throw new Exception();
		}
	}
}
