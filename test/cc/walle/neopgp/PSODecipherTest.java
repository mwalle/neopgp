// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import org.junit.Test;

public class PSODecipherTest extends JcardsimTestCase {
	@Test public void generateDecryptionKey() {
		admin();
		assertResponseOK("00478000000002B8000000");
	}

	@Test public void decipherWithECKey() {
		String req =
			"00 2A 80 86 48 A6 46 7F 49 43 86 41 04 16 42 70" +
			"CB 1B E7 E2 13 0C 35 4C B4 C3 B7 D1 92 B7 B6 47" +
			"EB 5D B8 A2 F0 E2 1A 4A 88 3A 8B C9 83 BE 1B E5" +
			"94 4E 51 29 13 A2 80 7E 3A 93 3E F3 28 FC F3 08" +
			"2A 3A 8C 4A 77 8A C9 CB 54 9B 55 EF 83 00";
		admin();
		changeKey(NeoKey.DECRYPTION_KEY, NeoKey.ALGORITHM_ID_ECDH);
		assertResponseOK("00478000000002B8000000");
		user();
		assertResponseOK(req);
	}

	@Test public void decipherWithECKeyNoAuthentication() {
		String req =
			"00 2A 80 86 48 A6 46 7F 49 43 86 41 04 16 42 70" +
			"CB 1B E7 E2 13 0C 35 4C B4 C3 B7 D1 92 B7 B6 47" +
			"EB 5D B8 A2 F0 E2 1A 4A 88 3A 8B C9 83 BE 1B E5" +
			"94 4E 51 29 13 A2 80 7E 3A 93 3E F3 28 FC F3 08" +
			"2A 3A 8C 4A 77 8A C9 CB 54 9B 55 EF 83 00";
		admin();
		changeKey(NeoKey.DECRYPTION_KEY, NeoKey.ALGORITHM_ID_ECDH);
		assertResponseOK("00478000000002B8000000");
		assertResponseStatus(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, req);
	}
}
