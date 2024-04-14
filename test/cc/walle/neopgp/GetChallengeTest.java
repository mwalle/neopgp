// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import org.junit.Test;

public class GetChallengeTest extends JcardsimTestCase {
	@Test public void getChallenge() {
		assertResponseLength(16 , "0084000010");
	}

	@Test public void getChallengeMaxLength() {
		assertResponseLength(128 , "0084000080");
	}

	@Test public void getChallengeOversize() {
		assertResponseLength(128 , "0084000081");
	}

	@Test public void getChallengeOversizeZero() {
		assertResponseLength(128 , "0084000000");
	}

	@Test public void getChallengeOversizeExtendedLength() {
		assertResponseLength(128 , "00840000001000");
	}
}
