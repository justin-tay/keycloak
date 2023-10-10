/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.crypto.elytron.test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.elytron.ElytronEcdhEsAlgorithmProvider;

public class ElytronEcdhEsAlgorithmProviderTest {

    /**
     * Test ECDH-ES Key Agreement Computation.
     *
     * @see <a href=
     *      "https://datatracker.ietf.org/doc/html/rfc7518#appendix-C">Example
     *      ECDH-ES Key Agreement Computation</a>
     * @throws InvalidKeySpecException  exception
     * @throws NoSuchAlgorithmException exception
     * @throws NoSuchProviderException  exception
     * @throws IllegalStateException    exception
     * @throws InvalidKeyException      exception
     */
    @Test
    public void deriveKey() throws JoseException, InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
        PrivateKey ephemeralPrivateKey = getPrivateKey("P-256", "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo");
        PublicKey encryptionPublicKey = getPublicKey("P-256", "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck");
        byte[] derivedKey = ElytronEcdhEsAlgorithmProvider.deriveKey(encryptionPublicKey, ephemeralPrivateKey, 128,
                "A128GCM", Base64Url.decode("QWxpY2U"), Base64Url.decode("Qm9i"));
        Assert.assertEquals("VqqN6vgjbSBcIijNcacQGg", Base64Url.encode(derivedKey));
    }

    private PublicKey getPublicKey(String crv, String xStr, String yStr) throws JoseException {
        BigInteger x = new BigInteger(1, Base64Url.decode(xStr));
        BigInteger y = new BigInteger(1, Base64Url.decode(yStr));
        EcKeyUtil ecKeyUtil = new EcKeyUtil();
        return ecKeyUtil.publicKey(x, y, EllipticCurves.getSpec(crv));
    }

    private PrivateKey getPrivateKey(String crv, String dStr) throws JoseException {
        BigInteger d = new BigInteger(1, Base64Url.decode(dStr));
        EcKeyUtil ecKeyUtil = new EcKeyUtil();
        return ecKeyUtil.privateKey(d, EllipticCurves.getSpec(crv));
    }
}