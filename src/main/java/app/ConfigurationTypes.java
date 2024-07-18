package app;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.tls.TlsUtils;

import app.ConfigurationTypes.HashAlgo;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.SignatureScheme;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;

public class ConfigurationTypes {
    private static final Logger LOGGER = LogManager.getLogger();

    public enum TlsVersion {
        TLS12,
        TLS13,
    }

    public enum KeyExchange {
        ECDHE,
        DHE,
        DH,
        RSA,
    }

    public static enum KeyExchangeGroup {
        NONE,
        
        // Elliptic Curve Groups
        SECP256R1,
        SECP384R1,
        SECP521R1,
        X25519,
        X448,

        // Finite Field Groups
        FFDHE2048,
        FFDHE3072,
        FFDHE4096,
        FFDHE6144,
        FFDHE8192,
    }

    public enum ServerAuth {
        DSA,
        ECDSA,
        RSA,
    }
    
    public enum ClientAuthCert {
        RSA,
        DSS,
        ECDSA,
        DH
    }

    public static class ClientAuthConfig {
        public CustomPrivateKey privKey;
        public ClientAuthCert certType;
        public org.bouncycastle.crypto.tls.Certificate cert;

        public ClientAuthConfig(ClientAuthCert certType, String certFilePath, CustomPrivateKey privateKey) {
            this.privKey = privateKey;
            this.certType = certType; 

            try {
                File certFile = new File(certFilePath);
                // read in certificate
                InputStream fileInputStream = new FileInputStream(certFile);
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends java.security.cert.Certificate> certs =
                        certFactory.generateCertificates(fileInputStream);
                java.security.cert.Certificate sunCert =
                        (java.security.cert.Certificate) certs.toArray()[0];
                byte[] certBytes = sunCert.getEncoded();
                ASN1Primitive asn1Cert = TlsUtils.readASN1Object(certBytes);
                org.bouncycastle.asn1.x509.Certificate cert =
                        org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
                org.bouncycastle.asn1.x509.Certificate[] certArray = new org.bouncycastle.asn1.x509.Certificate[]{cert};
                org.bouncycastle.crypto.tls.Certificate tlsCerts =
                    new org.bouncycastle.crypto.tls.Certificate(certArray);
                //ByteArrayOutputStream out = new ByteArrayOutputStream();
                //tlsCerts.encode(out);
                this.cert = tlsCerts;
            } catch (Exception ex) {
                throw new Error("Couldn't read in files. Error occured: " + ex);
            }
        }
    }

    public enum HashAlgo {
        SHA256,
        SHA384,
    }

    public enum Extension {
        OCSP,
        ZERO_RTT,
        RESUMPTION_SESSION_ID,
        RESUMPTION_SESSION_TICKET,
    }

    public enum BulkAlgo {
        AES_128_GCM,
        AES_256_GCM,
        AES_256_CBC,
        AES_128_CBC,
    }

    public enum SignatureScheme {
        DSA_SHA256,
        DSA_SHA384,
        ECDSA_SHA256,
        ECDSA_SHA384,
        RSA_SHA256,
        RSA_SHA384,
    }

    public static SignatureScheme combineAuthWithHash(ServerAuth serverAuth, HashAlgo hashAlgo) {
        switch (hashAlgo) {
            case SHA256:
                switch (serverAuth) {
                    case DSA:
                        return SignatureScheme.DSA_SHA256;
                    case ECDSA:
                        return SignatureScheme.ECDSA_SHA256;
                    case RSA:
                        return SignatureScheme.RSA_SHA256;
                }
            case SHA384:
                switch (serverAuth) {
                    case DSA:
                        return SignatureScheme.DSA_SHA384;
                    case ECDSA:
                        return SignatureScheme.ECDSA_SHA384;
                    case RSA:
                        return SignatureScheme.RSA_SHA384;
                }
        }
        throw new Error("No matching SignatureScheme found for: " + serverAuth + ", " + hashAlgo);
    }
    }
