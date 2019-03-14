package de.soderer.utilities;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

public class OID {
	/**
	 * OID for elliptic curve secp256 and nistp256
	 * OID 1.2.840.10045.3.1.7
	 */
	public static byte[] SECP256R1_ARRAY = new byte[] { 42, -122, 72, -50, 61, 3, 1, 7 };

	/**
	 * OID for elliptic curve secp384 and nistp384
	 * OID 1.3.132.0.34
	 */
	public static byte[] SECP384R1_ARRAY = new byte[] { 43, -127, 4, 0, 34 };

	/**
	 * OID for elliptic curve secp521 and nistp521
	 * OID 1.3.132.0.35
	 */
	public static byte[] SECP521R1_ARRAY = new byte[] { 43, -127, 4, 0, 35 };

	private int[] id;

	public OID(final String oidString) throws Exception {
		if (oidString == null || "".equals(oidString.trim())) {
			throw new Exception("Invalid OID empty data");
		} else {
			final String[] parts = oidString.split("\\.");
			id = new int[parts.length];
			for (int i = 0; i < parts.length; i++) {
				try {
					id[i] = Integer.parseInt(parts[i]);
				} catch (final Exception e) {
					throw new Exception("Invalid OID data: " + oidString);
				}
			}
		}
	}

	public OID(final byte[] oidArray) throws Exception {
		if (oidArray == null || oidArray.length == 0) {
			throw new Exception("Invalid OID empty data");
		} else {
			final List<Integer> idList = new ArrayList<>();
			if (oidArray.length > 0) {
				idList.add(oidArray[0] / 40);
				idList.add(oidArray[0] % 40);
			}
			for (int i = 1; i < oidArray.length; i++) {
				idList.add((int) decodeInteger(oidArray, i));
				while ((oidArray[i] & 0x80) != 0 && i + 1 < oidArray.length) {
					i++;
				}
			}
			id = idList.stream().mapToInt(Integer::intValue).toArray();
		}
	}

	public String getStringEncoding() {
		final StringBuilder returnValue = new StringBuilder();
		for (final int idPart : id) {
			if (returnValue.length() > 0) {
				returnValue.append(".");
			}
			returnValue.append(idPart);
		}
		return returnValue.toString();
	}

	public byte[] getByteArrayEncoding() throws Exception {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();

		if (id.length >= 1) {
			byte firstByte = (byte) (40 * id[0]);
			if (id.length >= 2) {
				firstByte = (byte) (firstByte + id[1]);
			}
			out.write(firstByte);
		}

		for (int i = 2; i < id.length; i++) {
			out.write(encodeInteger(id[i]));
		}

		return out.toByteArray();
	}

	public static byte[] encodeInteger(final long value) throws Exception {
		if (value < 0) {
			throw new Exception("Minimum encoded Integer underrun");
		} else if (value < 0x80) {
			return new byte[] { (byte) value };
		} else {
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			long buffer = value;
			out.write((byte) (buffer & 0x7F));
			buffer = (buffer >> 7);
			while (buffer > 0) {
				out.write((byte) (0x80 | (buffer & 0x7F)));
				buffer = buffer >> 7;
			}
			final byte[] returnArray = out.toByteArray();
			for (int i = 0; i < returnArray.length / 2; i++) {
				final byte swap = returnArray[i];
				returnArray[i] = returnArray[returnArray.length - 1 - i];
				returnArray[returnArray.length - 1 - i] = swap;
			}
			return returnArray;
		}
	}

	public static long decodeInteger(final byte[] array, final int startIndex) throws Exception {
		if (array.length == 0 || startIndex >= array.length) {
			throw new Exception("Invalid encoded Integer data");
		} else {
			long returnValue = 0;
			for (int i = startIndex; i < array.length; i++) {
				final boolean isLastByteOfValue = (array[i] & 0x80) == 0;
				returnValue <<= 7;
				returnValue += array[i] & 0x7F;
				if (isLastByteOfValue) {
					return returnValue;
				}
			}
			throw new Exception("Invalid encoded Integer data: Final byte sign is missing");
		}
	}
}
