package de.soderer.utilities.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;

import de.soderer.utilities.KeyPairUtilities;
import de.soderer.utilities.PuttyKey;
import de.soderer.utilities.PuttyKeyReader;
import de.soderer.utilities.PuttyKeyWriter;

public class PuttyKeyTest {
	public static void main(final String[] args) {
		try {
			new PuttyKeyTest().testRsa();
			new PuttyKeyTest().testDsa();
			new PuttyKeyTest().testEc256();
			new PuttyKeyTest().testEc384();
			new PuttyKeyTest().testEc521();

			System.out.println("Test passed successfully");
		} catch (final Exception e) {
			System.out.println("Test failed: " + e.getMessage());
		}
	}

	public void testRsa() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);

		final String sha256Fingerprint = KeyPairUtilities.getSha256Fingerprint(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (PuttyKeyWriter writer = new PuttyKeyWriter(byteArrayOutStream)) {
				writer.writeKey(new PuttyKey("Test key", keyPair), "password".toCharArray());
			}
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		if (!new String(data, "UTF-8").contains("PuTTY-User-Key-File-2")) {
			throw new Exception();
		}

		PuttyKey readPuttyKey;
		try (PuttyKeyReader reader = new PuttyKeyReader(new ByteArrayInputStream(data))) {
			readPuttyKey = reader.readKey("password".toCharArray());
		}
		final String readsha256Fingerprint = readPuttyKey.getSha256Fingerprint();
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(readsha256Fingerprint.toUpperCase().replace(":", ""))) {
			throw new Exception();
		}
	}

	public void testDsa() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createDsaKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256Fingerprint(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (PuttyKeyWriter writer = new PuttyKeyWriter(byteArrayOutStream)) {
				writer.writeKey(new PuttyKey("Test key", keyPair), "password".toCharArray());
			}
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		if (!new String(data, "UTF-8").contains("PuTTY-User-Key-File-2")) {
			throw new Exception();
		}

		PuttyKey readPuttyKey;
		try (PuttyKeyReader reader = new PuttyKeyReader(new ByteArrayInputStream(data))) {
			readPuttyKey = reader.readKey("password".toCharArray());
		}
		final String readsha256Fingerprint = readPuttyKey.getSha256Fingerprint();
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(readsha256Fingerprint.toUpperCase().replace(":", ""))) {
			throw new Exception();
		}
	}

	public void testEc256() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");

		final String sha256Fingerprint = KeyPairUtilities.getSha256Fingerprint(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (PuttyKeyWriter writer = new PuttyKeyWriter(byteArrayOutStream)) {
				writer.writeKey(new PuttyKey("Test key", keyPair), "password".toCharArray());
			}
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		if (!new String(data, "UTF-8").contains("PuTTY-User-Key-File-2")) {
			throw new Exception();
		}

		PuttyKey readPuttyKey;
		try (PuttyKeyReader reader = new PuttyKeyReader(new ByteArrayInputStream(data))) {
			readPuttyKey = reader.readKey("password".toCharArray());
		}
		final String readsha256Fingerprint = readPuttyKey.getSha256Fingerprint();
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(readsha256Fingerprint.toUpperCase().replace(":", ""))) {
			throw new Exception();
		}
	}

	public void testEc384() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");

		final String sha256Fingerprint = KeyPairUtilities.getSha256Fingerprint(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (PuttyKeyWriter writer = new PuttyKeyWriter(byteArrayOutStream)) {
				writer.writeKey(new PuttyKey("Test key", keyPair), "password".toCharArray());
			}
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		if (!new String(data, "UTF-8").contains("PuTTY-User-Key-File-2")) {
			throw new Exception();
		}

		PuttyKey readPuttyKey;
		try (PuttyKeyReader reader = new PuttyKeyReader(new ByteArrayInputStream(data))) {
			readPuttyKey = reader.readKey("password".toCharArray());
		}
		final String readsha256Fingerprint = readPuttyKey.getSha256Fingerprint();
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(readsha256Fingerprint.toUpperCase().replace(":", ""))) {
			throw new Exception();
		}
	}

	public void testEc521() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp521");

		final String sha256Fingerprint = KeyPairUtilities.getSha256Fingerprint(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			try (PuttyKeyWriter writer = new PuttyKeyWriter(byteArrayOutStream)) {
				writer.writeKey(new PuttyKey("Test key", keyPair), "password".toCharArray());
			}
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		if (!new String(data, "UTF-8").contains("PuTTY-User-Key-File-2")) {
			throw new Exception();
		}

		PuttyKey readPuttyKey;
		try (PuttyKeyReader reader = new PuttyKeyReader(new ByteArrayInputStream(data))) {
			readPuttyKey = reader.readKey("password".toCharArray());
		}
		final String readsha256Fingerprint = readPuttyKey.getSha256Fingerprint();
		if (!sha256Fingerprint.toUpperCase().replace(":", "").equals(readsha256Fingerprint.toUpperCase().replace(":", ""))) {
			throw new Exception();
		}
	}
}
