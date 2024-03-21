// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import org.junit.Test;

public class PSOSignatureTest extends JcardsimTestCase {
	@Test public void generateSignature() {
		admin();
		assertResponseOK("00478000000002B6000000");
		assertResponseOK(
			"002A9E9A533051300D06096086480165030402030500044093BFAC45A3D9EC01" +
			"9536A9F60DAA246283EBA5EC892E09AFEA289B37D956A6C46D74F5ECE076A6EF" +
			"392C7728045C1403F0C758C3BC01826E29697E8CF78A4B8E00");
	}
}
