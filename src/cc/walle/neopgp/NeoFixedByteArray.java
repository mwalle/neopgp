// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class NeoFixedByteArray extends NeoByteArray {
	public NeoFixedByteArray(short maxLength) {
		super(maxLength);
	}

	public NeoFixedByteArray(short maxLength, byte[] defaultValue) {
		super(maxLength, defaultValue);
		if (defaultValue.length != data.length)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	public short setNonAtomic(byte[] buf, short off, short len) {
		if (len != data.length)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		return super.setNonAtomic(buf, off, len);
	}

	short getLength() {
		return (short)data.length;
	}
}
