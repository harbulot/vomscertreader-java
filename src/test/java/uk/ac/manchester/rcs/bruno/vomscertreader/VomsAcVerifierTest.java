/**

Copyright (c) 2008-2010, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot
 
 */
package uk.ac.manchester.rcs.bruno.vomscertreader;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.voms.VOMSAttribute;
import org.junit.Before;
import org.junit.Test;

import uk.ac.manchester.rcs.bruno.vomscertreader.VomsAcVerifier;
import uk.ac.manchester.rcs.bruno.vomscertreader.VomsPrincipal;

public class VomsAcVerifierTest {
    public Collection<X509Certificate> getVomsIssuerCertificates()
            throws IOException {
        Collection<X509Certificate> certificates = new ArrayList<X509Certificate>();
        InputStreamReader certReader = new InputStreamReader(
                VomsAcVerifierTest.class
                        .getResourceAsStream("voms-ngs-ac-uk.pem"));
        PEMReader pemReader = new PEMReader(certReader);
        while (pemReader.ready()) {
            Object pemObject = pemReader.readObject();
            if (pemObject instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) pemObject;
                certificates.add(x509Certificate);
                System.out.println("CA X509Certificate: "
                        + x509Certificate.getSubjectX500Principal());
            } else {
                System.out.println("Unknown type of PEM object: " + pemObject);
            }
        }
        pemReader.close();
        return certificates;
    }

    public KeyStore getVomsIssuerKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        int i = 1;
        for (X509Certificate cert : getVomsIssuerCertificates()) {
            keyStore.setCertificateEntry("cert" + i, cert);
        }
        return keyStore;
    }

    @Before
    public void setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void readCertChain() throws Exception {
        InputStreamReader certReader = new InputStreamReader(
                VomsAcVerifierTest.class
                        .getResourceAsStream("gridproxychain.pem"));
        PEMReader pemReader = new PEMReader(certReader);

        List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();
        while (pemReader.ready()) {
            Object pemObject = pemReader.readObject();
            if (pemObject instanceof X509Certificate) {
                x509Certificates.add((X509Certificate) pemObject);
            }
        }
        pemReader.close();
    }

    @Test
    public void testExtractFQAN() throws Exception {
        InputStreamReader certReader = new InputStreamReader(
                VomsAcVerifierTest.class
                        .getResourceAsStream("gridproxychain.pem"));
        PEMReader pemReader = new PEMReader(certReader);

        List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();
        while (pemReader.ready()) {
            Object pemObject = pemReader.readObject();
            if (pemObject instanceof X509Certificate) {
                x509Certificates.add((X509Certificate) pemObject);
            }
        }
        pemReader.close();

        SimpleDateFormat dateFormat = new SimpleDateFormat(
                "EEE MMM dd HH:mm:ss zzz yyyy");
        Date validationDate = dateFormat.parse("Wed Feb 18 18:06:10 GMT 2009");

        VomsAcVerifier vomsAcVerifier = new VomsAcVerifier(this
                .getVomsIssuerKeyStore());
        List<VOMSAttribute.FQAN> fqas = vomsAcVerifier.extractFQAN(
                x509Certificates, validationDate);

        assertEquals(2, fqas.size());
        VOMSAttribute.FQAN fqa = fqas.get(0);
        assertEquals("NULL", fqa.getCapability());
        assertEquals("/nanocmos.ac.uk", fqa.getGroup());
        assertEquals("VO-Admin", fqa.getRole());

        fqa = fqas.get(1);
        assertEquals("NULL", fqa.getCapability());
        assertEquals("/nanocmos.ac.uk", fqa.getGroup());
        assertEquals("NULL", fqa.getRole());
    }

    @Test
    public void testExtractPrincipals() throws Exception {
        InputStreamReader certReader = new InputStreamReader(
                VomsAcVerifierTest.class
                        .getResourceAsStream("gridproxychain.pem"));
        PEMReader pemReader = new PEMReader(certReader);

        List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();
        while (pemReader.ready()) {
            Object pemObject = pemReader.readObject();
            if (pemObject instanceof X509Certificate) {
                x509Certificates.add((X509Certificate) pemObject);
            }
        }
        pemReader.close();

        SimpleDateFormat dateFormat = new SimpleDateFormat(
                "EEE MMM dd HH:mm:ss zzz yyyy");
        Date validationDate = dateFormat.parse("Wed Feb 18 18:06:10 GMT 2009");

        VomsAcVerifier vomsAcVerifier = new VomsAcVerifier(this
                .getVomsIssuerKeyStore());
        List<? extends VomsPrincipal> principals = vomsAcVerifier
                .extractVomsPrincipals(x509Certificates, validationDate);

        assertEquals(2, principals.size());
        VomsPrincipal principal = principals.get(0);
        assertEquals("/nanocmos.ac.uk/Role=VO-Admin/Capability=NULL", principal
                .getName());
        assertEquals("NULL", principal.getCapability());
        assertEquals("/nanocmos.ac.uk", principal.getGroup());
        assertEquals("VO-Admin", principal.getRole());

        principal = principals.get(1);
        assertEquals("/nanocmos.ac.uk/Role=NULL/Capability=NULL", principal
                .getName());
        assertEquals("NULL", principal.getCapability());
        assertEquals("/nanocmos.ac.uk", principal.getGroup());
        assertEquals("NULL", principal.getRole());
    }
}
