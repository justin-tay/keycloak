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
package org.keycloak.testsuite.broker;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.models.utils.DefaultKeyProviders;
import org.keycloak.representations.idm.ComponentExportRepresentation;

public class KcOidcBrokerJWEEcdhEs192KwA192GcmTest extends KcOidcBrokerJWETest {

    public KcOidcBrokerJWEEcdhEs192KwA192GcmTest() {
        super(JWEConstants.ECDH_ES_A192KW, JWEConstants.A192GCM, Algorithm.ES384);
    }

    protected ComponentExportRepresentation getProviderKeyProvider() {
        // create the ECDH component for the encryption in the specified alg
        ComponentExportRepresentation component = new ComponentExportRepresentation();
        component.setName("ecdsa-generated");
        component.setProviderId("ecdsa-generated");

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle("priority", DefaultKeyProviders.DEFAULT_PRIORITY);
        config.putSingle("ecdsaEllipticCurveKey", "P-384");
        component.setConfig(config);

        return component;
    }

    protected ComponentExportRepresentation getConsumerKeyProvider() {
        // create the ECDH component for the encryption in the specified alg
        ComponentExportRepresentation component = new ComponentExportRepresentation();
        component.setName("ecdh-generated");
        component.setProviderId("ecdh-generated");

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle("priority", DefaultKeyProviders.DEFAULT_PRIORITY);
        config.putSingle("ecdhAlgorithmMode", "Key wrapping mode");
        config.putSingle("ecdhEllipticCurveKey", "P-384");
        component.setConfig(config);

        return component;
    }
}
