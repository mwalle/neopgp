// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import static org.junit.Assert.*;
import org.junit.Test;

public class BERTLVTest {
	byte[] simpleTLV = { (byte)0xde, (byte)0xad, (byte)0x02, (byte)0x02, (byte)0x11, (byte)0x22 };
	byte[] doubleByteTagTLV = { (byte)0xde, (byte)0xad, (byte)0x7f, (byte)0x34, (byte)0x03, (byte)0x11, (byte)0x22, (byte)0x33};

	@Test
	public void simpleTLVLength() {
		assertEquals(2, BERTLV.getLength(simpleTLV, (short)2));
	}

	@Test
	public void simpleTLVGetTag() {
		byte[] tmp = new byte[1];
		assertEquals(1, BERTLV.getTag(simpleTLV, (short)2, tmp, (short)0));
		assertArrayEquals(new byte[] { (byte)0x02 }, tmp);
	}

	@Test
	public void doubleByteTagTLVLength() {
		assertEquals(3, BERTLV.getLength(doubleByteTagTLV, (short)2));
	}

	@Test
	public void doubleByteTagTLVGetTag() {
		byte[] tmp = new byte[2];
		assertEquals(2, BERTLV.getTag(doubleByteTagTLV, (short)2, tmp, (short)0));
		assertArrayEquals(new byte[] { (byte)0x7f, (byte)0x34 }, tmp);
	}

}
