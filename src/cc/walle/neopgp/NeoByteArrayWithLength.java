// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class NeoByteArrayWithLength extends NeoByteArray {
	short length;

	public NeoByteArrayWithLength(short maxLength) {
		super(maxLength);
		length = 0;
	}

	public NeoByteArrayWithLength(short maxLength, byte[] defaultValue) {
		super(maxLength, defaultValue);
		length = 0;
	}

	public short setNonAtomic(byte[] buf, short off, short len) {
		length = len;
		return super.setNonAtomic(buf, off, len);
	}

	short getLength() {
		return length;
	}

	public void clear() {
		if (defaultValue != null)
			length = (short)defaultValue.length;
		else
			length = 0;
		super.clear();
	}
}
