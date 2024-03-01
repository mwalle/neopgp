// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import static org.junit.Assert.*;
import org.junit.Test;
import javacardx.framework.tlv.TLVException;

public class PrimitiveBERTLVTest {
	byte[] simpleTLV = { (byte)0xde, (byte)0xad, (byte)0x02, (byte)0x02, };
	byte[] twoByteTagTwoByteLengthTLV = { (byte)0xde, (byte)0xad, (byte)0x1f, (byte)0x34, (byte)0x81, (byte)0x80 };
	byte[] threeByteLengthTLV = { (byte)0xde, (byte)0xad, (byte)0x02, (byte)0x82, (byte)0x10, (byte)0x00 };
	byte[] fourByteLengthTLV = { (byte)0xde, (byte)0xad, (byte)0x02, (byte)0x83, (byte)0x10, (byte)0x00, (byte)0x00};

	@Test
	public void simpleTLV() {
		assertEquals(4, PrimitiveBERTLV.getValueOffset(simpleTLV, (short)2));
	}

	@Test
	public void twoByteTagTwoByteLengthTLV() {
		assertEquals(6, PrimitiveBERTLV.getValueOffset(twoByteTagTwoByteLengthTLV, (short)2));
	}

	@Test
	public void threeByteLengthTLV() {
		assertEquals(6, PrimitiveBERTLV.getValueOffset(threeByteLengthTLV, (short)2));
	}

	@Test
	public void fourByteLengthTLV() {
		TLVException e = assertThrows(TLVException.class,
			() -> PrimitiveBERTLV.getValueOffset(fourByteLengthTLV, (short)2));
		assertEquals(TLVException.TLV_SIZE_GREATER_THAN_32767, e.getReason());
	}
}
