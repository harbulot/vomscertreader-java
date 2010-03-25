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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.voms.VOMSAttribute;
import org.bouncycastle.x509.X509V2AttributeCertificate;

/**
 * This class provides methods to verify a VOMS Attribute Certificate (AC)
 * contained in a proxy certificate and to extract its VOMS attributes.
 * 
 * {@link http://forge.gridforum.org/sf/go/doc13797?nav=1}
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class VomsAcVerifier {
    public final static String VOMS_AC_EXTENSION_OID = "1.3.6.1.4.1.8005.100.100.5";

    Collection<Certificate> trustedVomsIssuers = new ArrayList<Certificate>();

    /**
     * Initialises a VOMS AC Verifier with a set of trusted anchors. These trust
     * anchors are for the AC certificate issuer, not the verification of the
     * holder's chain.
     * 
     * @param trustStore
     * @throws KeyStoreException
     * @throws InvalidAlgorithmParameterException
     */
    public VomsAcVerifier(KeyStore trustStore) throws KeyStoreException,
            InvalidAlgorithmParameterException {
        PKIXParameters pkixParameters = new PKIXParameters(trustStore);
        for (TrustAnchor ta : pkixParameters.getTrustAnchors()) {
            this.trustedVomsIssuers.add(ta.getTrustedCert());
        }
    }

    /**
     * Gets the VomsPrincipals corresponding to the attributes in the VOMS ACs
     * present in the first certificate in the chain. VOMS AC holder's is the
     * user's public key certificate, not the proxy certificate containing the
     * AC.
     * 
     * It is assumed that the proxy certificate chain has already been verified
     * by some other means. The trust anchors are only used for establishing
     * trust in the AC.
     * 
     * @param proxyCertificateChain
     *            chain of certificates, first one being the AC container, but
     *            also containing the holder (non-proxy).
     * @return VomsPrincipals for the attributes in the VOMS AC.
     * @throws CertificateException
     */
    public Collection<? extends VomsPrincipal> getVomsPrincipals(
            List<? extends X509Certificate> proxyCertificateChain)
            throws CertificateException {
        return extractVomsPrincipals(proxyCertificateChain, new Date());
    }

    /**
     * Gets the VomsPrincipals corresponding to the attributes in the VOMS ACs
     * present in the first certificate in the chain. VOMS AC holder's is the
     * user's public key certificate, not the proxy certificate containing the
     * AC.
     * 
     * It is assumed that the proxy certificate chain has already been verified
     * by some other means. The trust anchors are only used for establishing
     * trust in the AC.
     * 
     * @param proxyCertificateChain
     *            chain of certificates, first one being the AC container, but
     *            also containing the holder (non-proxy).
     * @param validationDate
     *            validation date
     * @return VomsPrincipals for the attributes in the VOMS AC.
     * @throws CertificateException
     */
    public Collection<? extends VomsPrincipal> getVomsPrincipals(
            List<? extends X509Certificate> proxyCertificateChain,
            Date validationDate) throws CertificateException {
        return extractVomsPrincipals(proxyCertificateChain, validationDate);
    }

    /**
     * This class extracts the VOMS attributes from the AC certificate contained
     * in the first certificate in the chain.
     * 
     */
    protected List<VOMSAttribute.FQAN> extractFQAN(
            List<? extends X509Certificate> proxyCertificateChain,
            Date validationDate) throws CertificateException {
        try {
            byte[] attrCertExtensionValue = proxyCertificateChain.get(0)
                    .getExtensionValue(VOMS_AC_EXTENSION_OID);

            if (attrCertExtensionValue == null) {
                return null;
            }

            ASN1InputStream asn1InputStream;
            DEREncodable derEncodable;

            asn1InputStream = new ASN1InputStream(attrCertExtensionValue);
            derEncodable = asn1InputStream.readObject();
            if ((derEncodable == null)
                    || !(derEncodable instanceof DEROctetString)) {
                throw new CertificateParsingException(String.format(
                        "Error while parsing extension %s.",
                        VOMS_AC_EXTENSION_OID));
            }
            DEROctetString encapsulatingOctetString = (DEROctetString) derEncodable;

            asn1InputStream = new ASN1InputStream(encapsulatingOctetString
                    .getOctetStream());
            derEncodable = asn1InputStream.readObject();
            if ((derEncodable == null)
                    || !(derEncodable instanceof ASN1Sequence)) {
                throw new CertificateParsingException(String.format(
                        "Error while parsing extension %s.",
                        VOMS_AC_EXTENSION_OID));
            }
            ASN1Sequence explictTagSequence = (ASN1Sequence) derEncodable;
            @SuppressWarnings("unchecked")
            Enumeration<DEREncodable> explictTagSequenceEnum = explictTagSequence
                    .getObjects();

            derEncodable = explictTagSequenceEnum.nextElement();
            if ((derEncodable == null)
                    || !(derEncodable instanceof ASN1Sequence)) {
                throw new CertificateParsingException(String.format(
                        "Error while parsing extension %s.",
                        VOMS_AC_EXTENSION_OID));
            }
            ASN1Sequence acSequence = (ASN1Sequence) derEncodable;
            @SuppressWarnings("unchecked")
            Enumeration<DEREncodable> acSequenceEnum = acSequence.getObjects();

            if (!acSequenceEnum.hasMoreElements()) {
                return null;
            }

            List<VOMSAttribute.FQAN> vomsAttributeFQANs = new ArrayList<VOMSAttribute.FQAN>();
            while (acSequenceEnum.hasMoreElements()) {
                DEREncodable acDerEncodable = acSequenceEnum.nextElement();
                X509V2AttributeCertificate attrCert = new X509V2AttributeCertificate(
                        acDerEncodable.getDERObject().getDEREncoded());
                vomsAttributeFQANs.addAll(extractFQAN(proxyCertificateChain,
                        validationDate, attrCert));
            }

            return vomsAttributeFQANs;
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }

    /**
     * Verifies a VOMS AC and extracts the Fully Qualified Attribute Names of
     * its attributes.
     * 
     * @param holderCertificateChain
     *            certificate chain of the holder.
     * @param validationDate
     *            validation date (defaults to current date if null).
     * @param vomsAttributeCertificate
     *            the VOMS attribute certificate.
     * @return a list of VOMSAttribute.FQAN
     * @throws CertificateException
     *             This exception is thrown if something's wrong with the VOMS
     *             AC (e.g. can't be verified).
     */
    protected List<VOMSAttribute.FQAN> extractFQAN(
            List<? extends X509Certificate> holderCertificateChain,
            Date validationDate,
            X509V2AttributeCertificate vomsAttributeCertificate)
            throws CertificateException {
        /*
         * Check the time validity of the certificate (date/time).
         */
        if (validationDate == null) {
            validationDate = new Date();
        }
        vomsAttributeCertificate.checkValidity(validationDate);

        if (vomsAttributeCertificate.getHolder().getEntityNames() != null) {
            throw new CertificateException(
                    "VOMS Attribute Certificate Holder entity names MUST be absent");
        }

        if (vomsAttributeCertificate.getHolder().getObjectDigest() != null) {
            throw new CertificateException(
                    "VOMS Attribute Certificate Holder object digest MUST be absent");
        }

        boolean verifiedByTrustedIssuer = false;
        for (Certificate trustedCertificate : trustedVomsIssuers) {
            if (vomsAttributeCertificate.getIssuer().match(trustedCertificate)) {
                try {
                    vomsAttributeCertificate.verify(trustedCertificate
                            .getPublicKey(), "BC");
                    verifiedByTrustedIssuer = true;

                    /*
                     * Finds the end-entity certificate for the proxy
                     * certificate in which the VOMS AC was contained.
                     */
                    X509Certificate endEntityCertificate = null;
                    for (int i = 0; i < holderCertificateChain.size() - 1; i++) {
                        X509Certificate signer = holderCertificateChain
                                .get(i + 1);
                        if (signer.getBasicConstraints() >= 0) {
                            endEntityCertificate = holderCertificateChain
                                    .get(i);
                            break;
                        }
                    }

                    if (endEntityCertificate == null) {
                        endEntityCertificate = holderCertificateChain
                                .get(holderCertificateChain.size() - 1);
                    }

                    if (!vomsAttributeCertificate.getHolder().match(
                            endEntityCertificate)) {
                        throw new CertificateException(
                                "VOMS AC ceritifiate in proxy certificate wasn't issued for end-entity certificate in the proxy chain.");
                    }

                    break;
                } catch (InvalidKeyException e) {
                    continue;
                } catch (NoSuchAlgorithmException e) {
                    continue;
                } catch (NoSuchProviderException e) {
                    throw new RuntimeException(e);
                } catch (SignatureException e) {
                    continue;
                }
            }
        }

        if (!verifiedByTrustedIssuer) {
            throw new CertificateException(
                    "Unable to verify VOMS AC certificate against trusted VOMS issuer.");
        }

        VOMSAttribute vomsAttr = new VOMSAttribute(vomsAttributeCertificate);
        @SuppressWarnings("unchecked")
        List<VOMSAttribute.FQAN> fqas = (List<VOMSAttribute.FQAN>) vomsAttr
                .getListOfFQAN();
        return fqas;
    }

    /**
     * Build VomsPrincipals from the VOMS attributes.
     * 
     */
    protected List<? extends VomsPrincipal> extractVomsPrincipals(
            List<? extends X509Certificate> holderCertificateChain,
            Date validationDate) throws CertificateException {
        List<VOMSAttribute.FQAN> fqas = extractFQAN(holderCertificateChain,
                validationDate);
        ArrayList<VomsPrincipal> vomsPrincipals = new ArrayList<VomsPrincipal>();
        for (VOMSAttribute.FQAN fqa : fqas) {
            vomsPrincipals.add(new VomsPrincipal(fqa.getGroup(), fqa.getRole(),
                    fqa.getCapability()));
        }
        return vomsPrincipals;
    }
}
