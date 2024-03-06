// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class NeoKeyStore {
	private NeoKey[] keyStore;

	public NeoKeyStore(short bitmask) {
		short n = 0;

		bitmask &= 0x0007;
		for (short i = (short)1; (i & (short)0x3ff) != 0; i <<= 1)
			if ((bitmask & i) == i)
				n++;

		/* At least one key is needed */
		if (n == 0)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		keyStore = new NeoKey[n];

		n = 0;
		if ((bitmask & (short)0x0001) == (short)0x0001)
			keyStore[n++] = new NeoRSAKey((short)2048);
		if ((bitmask & (short)0x0002) == (short)0x0002)
			keyStore[n++] = new NeoRSAKey((short)3072);
		if ((bitmask & (short)0x0004) == (short)0x0004)
			keyStore[n++] = new NeoRSAKey((short)4096);
	}

	public NeoKey getDefaultKey() {
		return keyStore[0];
	}

	public void clear() {
		for (short i = 0; i < keyStore.length; i++)
			keyStore[i].clear();
	}
}
