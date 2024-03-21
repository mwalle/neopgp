// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import org.junit.Test;

public class GenerateKeyTest extends JcardsimTestCase {
	@Test public void generateSignatureKey() {
		admin();
		assertResponseOK("00478000000002B6000000");
	}

	@Test public void defaultResponseNoKey() {
		assertResponseStatus(0x6a88, "00478100000002B800010E");
	}
}

