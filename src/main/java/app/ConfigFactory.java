package app;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Vector;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.tls.TlsUtils;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.HashAlgo;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.KeyExchangeGroup;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.TlsVersion;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class ConfigFactory {
    private static final Logger LOGGER = LogManager.getLogger();

    public static Config getConfig(
            TlsVersion version,
            KeyExchange keyExchange,
            KeyExchangeGroup keyExchangeGroup,
            ServerAuth serverAuth,
            HashAlgo hashAlgo,
            BulkAlgo bulkAlgo,
            Vector<Extension> extensions) {

        ConfigError configValidity = validateConfigCombi(
                version,
                keyExchange,
                keyExchangeGroup,
                serverAuth,
                hashAlgo,
                bulkAlgo,
                extensions);
        if (configValidity != ConfigError.NO_ERROR) {
            throw new Error("Configuration is invalid (" + configValidity 
                + "):\n\tVersion: " + version 
                + "\n\tKey ex: " + keyExchange 
                + "\n\tServer auth: " + serverAuth 
                + "\n\tHash: " + hashAlgo 
                + "\n\tBulk: " + bulkAlgo
                + "\n\tExtensions: " + extensions.toString());
        }
    
        //Config myConfig = Config.createEmptyConfig();
        Config myConfig = Config.createConfig();
        
        // set TLS version
        switch (version) {
            case TLS12:
                myConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
                myConfig.setSupportedVersions(ProtocolVersion.TLS12);
                myConfig.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);
                break;
            case TLS13:
                myConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
                myConfig.setSupportedVersions(ProtocolVersion.TLS13);
                myConfig.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);

                // other TLS1.3 specific extensions
                myConfig.setAddKeyShareExtension(true);
                myConfig.setAddSupportedVersionsExtension(true);
                myConfig.setAddSignatureAndHashAlgorithmsExtension(true);        
                break;
            default:
                throw new Error("TLS version not supported: " + version);
        }

        // set signature and hash algorithm
        switch (ConfigurationTypes.combineAuthWithHash(serverAuth, hashAlgo)) {
            case DSA_SHA256:
                myConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.DSA_SHA256);
                break;
            case DSA_SHA384:
                myConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.DSA_SHA384);
                break;
            case ECDSA_SHA256:
                myConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.ECDSA_SHA256);
                break;
            case ECDSA_SHA384:
                myConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.ECDSA_SHA384);
                break;
            case RSA_SHA256:
                myConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_SHA256);
                break;
            case RSA_SHA384:
                myConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_SHA384);
                break;
            default:
                throw new Error("SignatureAndHashAlgorithm Scheme is not supported.");
        }

        // set cipher suite
        CipherSuite cipherSuite = matchCipher(version, keyExchange, serverAuth, bulkAlgo, hashAlgo);
        myConfig.setDefaultClientSupportedCipherSuites(cipherSuite);
        myConfig.setDefaultSelectedCipherSuite(cipherSuite);

        if (keyExchange == KeyExchange.ECDHE) {
            myConfig.setAddECPointFormatExtension(true);
        } else {
            myConfig.setAddECPointFormatExtension(false);
        }

        if (keyExchange == KeyExchange.ECDHE || keyExchange == KeyExchange.DHE) {
            myConfig.setAddEllipticCurveExtension(true);
        } else {
            myConfig.setAddEllipticCurveExtension(false);
        }

        // set key exchange group
        if (keyExchange != KeyExchange.RSA) { // meaning (EC)DH(E)
            NamedGroup namedGroup = getNamedGroup(keyExchangeGroup);
            myConfig.setDefaultClientNamedGroups(namedGroup);
            myConfig.setDefaultSelectedNamedGroup(namedGroup);
            myConfig.setDefaultClientKeyShareNamedGroups(namedGroup);
        }

        // Client authentication
        CertificateKeyPair certKeyPair;
        try {
            File myFile = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/keyGen/rsa2048_cert.pem");
            InputStream fileInputStream = new FileInputStream(myFile);
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
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            tlsCerts.encode(out);
            
            byte[] derEncdoedPrivKey = new byte[]{(byte)0x02, (byte)0x82, (byte)0x01, (byte)0x00, (byte)0x08, (byte)0x90, (byte)0x9E, (byte)0x8D, (byte)0xE7, (byte)0xAA, (byte)0x47, (byte)0x5D, (byte)0x12, (byte)0x3C, (byte)0x5B, (byte)0x03, (byte)0xA7, (byte)0x38, (byte)0xF6, (byte)0x89, (byte)0x9C, (byte)0x8A, (byte)0x70, (byte)0x10, (byte)0x6F, (byte)0x87, (byte)0xB7, (byte)0x8E, (byte)0x17, (byte)0xAE, (byte)0x69, (byte)0xD2, (byte)0x0F, (byte)0x25, (byte)0x98, (byte)0x67, (byte)0x92, (byte)0x02, (byte)0xD0, (byte)0xAE, (byte)0x7E, (byte)0xD7, (byte)0xCA, (byte)0x9C, (byte)0x5D, (byte)0xD5, (byte)0x97, (byte)0x21, (byte)0xB2, (byte)0xE1, (byte)0x0F, (byte)0x28, (byte)0x26, (byte)0x13, (byte)0x14, (byte)0xC6, (byte)0x35, (byte)0x1B, (byte)0x84, (byte)0xCF, (byte)0x68, (byte)0xC9, (byte)0xE7, (byte)0x1F, (byte)0x5F, (byte)0xC9, (byte)0x2A, (byte)0xED, (byte)0x04, (byte)0xBA, (byte)0x81, (byte)0xA5, (byte)0xE1, (byte)0x43, (byte)0xC6, (byte)0x10, (byte)0x0D, (byte)0x06, (byte)0x52, (byte)0xC7, (byte)0xE0, (byte)0x90, (byte)0x8F, (byte)0xE3, (byte)0x99, (byte)0x5B, (byte)0x9E, (byte)0x17, (byte)0x92, (byte)0xE9, (byte)0x80, (byte)0x45, (byte)0xCE, (byte)0x30, (byte)0xE8, (byte)0xAF, (byte)0xF5, (byte)0x7E, (byte)0xAD, (byte)0x3F, (byte)0xD7, (byte)0x03, (byte)0x02, (byte)0x4D, (byte)0x3B, (byte)0xBC, (byte)0x5A, (byte)0xC6, (byte)0xE7, (byte)0x5A, (byte)0xD0, (byte)0x1D, (byte)0xE3, (byte)0x42, (byte)0x71, (byte)0x56, (byte)0x98, (byte)0xF9, (byte)0x7E, (byte)0xBD, (byte)0xBF, (byte)0xE0, (byte)0x60, (byte)0x72, (byte)0xD2, (byte)0x45, (byte)0x4A, (byte)0x07, (byte)0x42, (byte)0xD2, (byte)0xBE, (byte)0x55, (byte)0x80, (byte)0xDD, (byte)0x05, (byte)0xB2, (byte)0xE2, (byte)0xBF, (byte)0x8C, (byte)0xF1, (byte)0x92, (byte)0x07, (byte)0x61, (byte)0x16, (byte)0x8B, (byte)0xDC, (byte)0x41, (byte)0x8A, (byte)0x63, (byte)0xD9, (byte)0x6C, (byte)0xC3, (byte)0x30, (byte)0xC8, (byte)0x35, (byte)0x5C, (byte)0xB3, (byte)0xE2, (byte)0x10, (byte)0x13, (byte)0x3E, (byte)0xB7, (byte)0x3E, (byte)0x79, (byte)0xD5, (byte)0xBB, (byte)0xFE, (byte)0xCE, (byte)0xDB, (byte)0xA4, (byte)0xEC, (byte)0xAD, (byte)0xB3, (byte)0xFD, (byte)0xAB, (byte)0x26, (byte)0xF5, (byte)0xBA, (byte)0xAC, (byte)0x89, (byte)0xC8, (byte)0x24, (byte)0x67, (byte)0x55, (byte)0xE0, (byte)0xD8, (byte)0xAB, (byte)0xDD, (byte)0xFE, (byte)0x2D, (byte)0x91, (byte)0x18, (byte)0x99, (byte)0xB7, (byte)0x30, (byte)0xDE, (byte)0xE3, (byte)0x2E, (byte)0xC9, (byte)0x7F, (byte)0x8D, (byte)0x90, (byte)0x59, (byte)0x7D, (byte)0xCE, (byte)0x82, (byte)0x37, (byte)0xCF, (byte)0x70, (byte)0xF7, (byte)0xA5, (byte)0x85, (byte)0xA0, (byte)0xEC, (byte)0x4D, (byte)0xEA, (byte)0x26, (byte)0x4A, (byte)0xA7, (byte)0xF6, (byte)0x4C, (byte)0xE1, (byte)0xFE, (byte)0x21, (byte)0x70, (byte)0xE3, (byte)0x3B, (byte)0x1B, (byte)0xB3, (byte)0x78, (byte)0x80, (byte)0xF2, (byte)0x02, (byte)0xC4, (byte)0x6C, (byte)0x2F, (byte)0x3E, (byte)0xFD, (byte)0xB9, (byte)0x1A, (byte)0x28, (byte)0x5B, (byte)0xC4, (byte)0x2E, (byte)0x31, (byte)0x8B, (byte)0x56, (byte)0x58, (byte)0xE4, (byte)0xA3, (byte)0xA1, (byte)0x0C, (byte)0xA5, (byte)0x24, (byte)0x4F, (byte)0xDA, (byte)0x62, (byte)0x5F, (byte)0x7F, (byte)0xFF};
            //CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP384R1);
            CustomRSAPrivateKey privKey = new CustomRSAPrivateKey(
                new BigInteger("22680894355213276814068604237379515326692913667424423179105887452289906651381282343803736135056197131595363416117766447222033440405148554595150495098954618784791409846721078014631997901600818192748951260294724453863786822963457535714201456929910107294028887630816463336166663178044202436591458723765695469483323295740091515251848862253753967572511917223940594872506608243732478287780716299338656301737923256700355562820768458403307832462075060029877854803131864443444034500618089480396072963994147799521776599695622459322293973138939514112920721100797951815691387710738229293066991665386400046197146008454129381303013"),
                new BigInteger("1081220900519306994054118481314527476163106719322647452617727838882406914114781299588271417902671126167388106236144671423388446493562843049877263993876061364494202266642979463380542895308994686679330955004731190982136777534172265998708970859053814947427221608823239751002807226391716969448091277902763492530629102587274894712676589402812658549391491035698540223575850258784236700772902034492790099278379171982874885903225435518252664651224422790750083966520867503120878596752239393242686207324374684442156551897779979099846701806053546967178413553042480432389633260063913612546788291398650159971518641894650833502207"));
            //System.out.println("PRIVKEY: " + privKey);

            certKeyPair = new CertificateKeyPair(tlsCerts, privKey);
            
            System.out.println("certKeyPair.getCertSignatureType: " + certKeyPair.getCertSignatureType());
            System.out.println("certKeyPair.getPublicKeyGroup: " + certKeyPair.getPublicKeyGroup());
            System.out.println("certKeyPair.getSignatureAlgorithm: " + certKeyPair.getSignatureAlgorithm());
            System.out.println("certKeyPair.getSignatureAndHashAlgorithm: " + certKeyPair.getSignatureAndHashAlgorithm());
            System.out.println("certKeyPair.getSignatureGroup: " + certKeyPair.getSignatureGroup());
        } catch (Exception ex) {
            throw new Error("Error occured: " + ex);
        }

        myConfig.setAutoSelectCertificate(false);
        myConfig.setDefaultExplicitCertificateKeyPair(certKeyPair);

        // add needed extensions
        // session resumption with ticket
        if (extensions.contains(Extension.RESUMPTION_SESSION_TICKET)) {
            myConfig.setAddSessionTicketTLSExtension(true);
            if (version == TlsVersion.TLS13) {
                List<PskKeyExchangeMode> pskList = new ArrayList<>();
                    pskList.add(PskKeyExchangeMode.PSK_DHE_KE);
                    myConfig.setPSKKeyExchangeModes(pskList);
                    myConfig.setAddPSKKeyExchangeModesExtension(true);
                    myConfig.setAddPreSharedKeyExtension(true);
            }
        }
        // session resumption based on session id
        else if (extensions.contains(Extension.RESUMPTION_SESSION_ID)) {
            myConfig.setAddSessionTicketTLSExtension(false);
        } else {
            myConfig.setAddSessionTicketTLSExtension(false);
            myConfig.setAddPSKKeyExchangeModesExtension(false);
            myConfig.setAddPreSharedKeyExtension(false);
        }

        // Early Data / 0RTT
        if (extensions.contains(Extension.ZERO_RTT)) {
            switch (version) {
                case TLS12:
                    throw new Error("ZERO_RTT is not supported for TLS1.2");
                case TLS13:
                    // early data extension
                    myConfig.setAddEarlyDataExtension(true);
                    myConfig.setEarlyData(new byte[]{0x54, 0x4C, 0x53, 0x2D, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6B, 0x65, 0x72, 0x0A});

                    // pre-shared key extension
                    List<PskKeyExchangeMode> pskList = new ArrayList<>();
                    pskList.add(PskKeyExchangeMode.PSK_KE);
                    myConfig.setPSKKeyExchangeModes(pskList);
                    myConfig.setAddPSKKeyExchangeModesExtension(true);
                    myConfig.setAddPreSharedKeyExtension(true);
                    break;
            }
        } else {
            myConfig.setAddEarlyDataExtension(false);
        }
        
        // OCSP
        if (extensions.contains(Extension.OCSP)) {
            myConfig.setAddCertificateStatusRequestExtension(true);
            myConfig.setCertificateStatusRequestExtensionRequestType(CertificateStatusRequestType.OCSP);
            //<certificateStatusRequestExtensionRequestType>OCSP</certificateStatusRequestExtensionRequestType>
        } else {
            myConfig.setAddCertificateStatusRequestExtension(false);
        }

        // Misc
        myConfig.setAddRenegotiationInfoExtension(false);

        System.out.println(getConfigOverview(myConfig));
        return myConfig;
    }

    private enum ConfigError {
        NO_ERROR,
        TLS13_WITH_STATIC_KX,
        TLS13_WITH_SESSION_ID_RESUMPTION,
        AMBIGIOUS_RESUMPTION,
        HASH_MISMATCHING_BULK,
    }

    private static ConfigError validateConfigCombi(
            TlsVersion version,
            KeyExchange keyExchange,
            KeyExchangeGroup keyExchangeGroup,
            ServerAuth serverAuth,
            HashAlgo hashAlgo,
            BulkAlgo bulkAlgo,
            Vector<Extension> extensions) {
        if (version == TlsVersion.TLS13 && keyExchange == KeyExchange.RSA
                || version == TlsVersion.TLS13 && keyExchange == KeyExchange.DH) {
            return ConfigError.TLS13_WITH_STATIC_KX;
        }

        if (version == TlsVersion.TLS13 && extensions.contains(Extension.RESUMPTION_SESSION_ID)){
            return ConfigError.TLS13_WITH_SESSION_ID_RESUMPTION;
        }

        if (extensions.contains(Extension.RESUMPTION_SESSION_ID) && extensions.contains(Extension.RESUMPTION_SESSION_TICKET)){
            return ConfigError.AMBIGIOUS_RESUMPTION;
        }          

        if (
            (bulkAlgo == BulkAlgo.AES_256_GCM && hashAlgo != HashAlgo.SHA384)
            || (bulkAlgo == BulkAlgo.AES_128_GCM && hashAlgo != HashAlgo.SHA256)
            || (bulkAlgo == BulkAlgo.AES_256_CBC && hashAlgo != HashAlgo.SHA384)
            || (bulkAlgo == BulkAlgo.AES_128_CBC && hashAlgo != HashAlgo.SHA256))
        {
            return ConfigError.HASH_MISMATCHING_BULK;
        }

        if (keyExchange == KeyExchange.ECDHE) {
            if (
                keyExchangeGroup != KeyExchangeGroup.SECP256R1
                && keyExchangeGroup != KeyExchangeGroup.SECP384R1
                && keyExchangeGroup != KeyExchangeGroup.SECP521R1
                && keyExchangeGroup != KeyExchangeGroup.X25519
                && keyExchangeGroup != KeyExchangeGroup.X448) {
                    throw new Error("KeyExchange is ECDHE but KeyExchangeGroup is non elliptic: " + keyExchangeGroup);
                }
        }
        if ((keyExchange == KeyExchange.DH) || (keyExchange == KeyExchange.DHE)) {
            if (
                keyExchangeGroup != KeyExchangeGroup.FFDHE2048
                && keyExchangeGroup != KeyExchangeGroup.FFDHE3072
                && keyExchangeGroup != KeyExchangeGroup.FFDHE4096
                && keyExchangeGroup != KeyExchangeGroup.FFDHE6144
                && keyExchangeGroup != KeyExchangeGroup.FFDHE8192) {
                    throw new Error("KeyExchange is DH(E) but KeyExchangeGroup is non finite group: " + keyExchangeGroup);
                }
        }
        if (keyExchange == KeyExchange.RSA) {
            if (keyExchangeGroup != KeyExchangeGroup.NONE) {
                    throw new Error("KeyExchange is RSA but KeyExchangeGroup is set: " + keyExchangeGroup);
                }
        }

        return ConfigError.NO_ERROR;
    }

    private static NamedGroup getNamedGroup(KeyExchangeGroup keyExchangeGroup) {
        switch (keyExchangeGroup) {
            case SECP256R1:
                return NamedGroup.SECP256R1;
            case SECP384R1:
                return NamedGroup.SECP384R1;
            case SECP521R1:
                return NamedGroup.SECP521R1;
            case X25519:
                return NamedGroup.ECDH_X25519;
            case X448:
                return NamedGroup.ECDH_X448;
            case FFDHE2048:
                return NamedGroup.FFDHE2048;
            case FFDHE3072:
                return NamedGroup.FFDHE3072;
            case FFDHE4096:
                return NamedGroup.FFDHE4096;
            case FFDHE6144:
                return NamedGroup.FFDHE6144;
            case FFDHE8192:
                return NamedGroup.FFDHE8192;
             default:
                throw new Error("There is no corresponding NamedGroup for the KeyExchangeGroup: " + keyExchangeGroup);
        }
    }

    private static class CipherDetails {
        CipherSuite cipher;
        TlsVersion version;
        KeyExchange keyExchange;
        ServerAuth serverAuth;
        BulkAlgo bulkAlgo;
        HashAlgo hashAlgo;
        
        CipherDetails(CipherSuite myCipher, TlsVersion myVersion, KeyExchange myKeyExchange, ServerAuth myServerAuth, BulkAlgo myBulkAlgo, HashAlgo myHashAlgo) {
            cipher = myCipher;
            version = myVersion;
            keyExchange = myKeyExchange;
            serverAuth = myServerAuth;
            bulkAlgo = myBulkAlgo;
            hashAlgo = myHashAlgo;
        }
    }

    private static CipherSuite matchCipher(TlsVersion version, KeyExchange keyExchange, ServerAuth serverAuth, BulkAlgo bulkAlgo, HashAlgo hashAlgo) {
        ArrayList<CipherDetails> ciphersOverview = new ArrayList<CipherDetails>();

        // TLS1.2 ciphers
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.RSA, ServerAuth.RSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.DHE, ServerAuth.RSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.RSA, BulkAlgo.AES_128_GCM, HashAlgo.SHA256));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.RSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.RSA, BulkAlgo.AES_128_CBC, HashAlgo.SHA256));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.RSA, BulkAlgo.AES_256_CBC, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.ECDSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.ECDSA, BulkAlgo.AES_128_GCM, HashAlgo.SHA256));
        
        // TLS1.3 ciphers
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_AES_128_GCM_SHA256, TlsVersion.TLS13, null, null, BulkAlgo.AES_128_GCM, HashAlgo.SHA256));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_AES_256_GCM_SHA384, TlsVersion.TLS13, null, null, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        
        for (CipherDetails cipherOverview: ciphersOverview) {
            // shared checks between TLS1.2 and TLS1.3
            if (cipherOverview.version != version) { continue; }
            if (cipherOverview.bulkAlgo != bulkAlgo) { continue; }
            if (cipherOverview.hashAlgo != hashAlgo) { continue; }        

            // differentiated checks for TLS1.2 and TLS1.3
            switch (cipherOverview.version) {
                case TLS12:
                    if (cipherOverview.keyExchange != keyExchange) { continue; }
                    if (cipherOverview.serverAuth != serverAuth) { continue; }
                    return cipherOverview.cipher;
                case TLS13:
                    if (cipherOverview.keyExchange != null) { continue; }
                    if (cipherOverview.serverAuth != null) { continue; }
                    return cipherOverview.cipher;
            }
        }
        
        throw new Error("No matching cipher suite found for:"
            + "\n\tversion: " + version
            + "\n\tkeyExchange: " + keyExchange
            + "\n\tServerAuth: " + serverAuth
            + "\n\tBulkAlgo: " + bulkAlgo
            + "\n\tHashAlgo: " + hashAlgo);
    }

    public static String getConfigOverview(Config config) {
        String configDescription = new String();

        configDescription = "Config\n";
        configDescription += "\nHighest TLS Version: " + config.getHighestProtocolVersion();
        configDescription += "\nCipher Suite: " + config.getDefaultSelectedCipherSuite();
        // TODO: ggf. deepstring nutzen, falls mehrere einträge möglich
        configDescription += "\nSig and Hash Algo: " + config.getDefaultClientSupportedSignatureAndHashAlgorithms();

        configDescription += "\nEC Point Extension: " + config.isAddECPointFormatExtension();
        configDescription += "\nEC Extension: " + config.isAddEllipticCurveExtension();
        
        configDescription += "\nNamed Group: " + config.getDefaultSelectedNamedGroup();
        configDescription += "\nKey Share: " + config.getDefaultClientKeyShareNamedGroups();
        
        configDescription += "\nOCSP: " + config.isAddCertificateStatusRequestExtension();

        configDescription += "\nSession Ticket Extension: " + config.isAddSessionTicketTLSExtension(); 
        if (config.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
            configDescription += "\nPSK Extension (TLS1.3): " + config.isAddPSKKeyExchangeModesExtension();
            configDescription += "\nPSK Extension (TLS1.3): " + config.isAddPreSharedKeyExtension();
            if (config.isAddPSKKeyExchangeModesExtension()) {
                configDescription += "\nPSK Exchange Modes (TLS1.3): " + config.getPSKKeyExchangeModes();
            }
            
            configDescription += "\nEarly Data Extension (TLS1.3): " + config.isAddEarlyDataExtension();
            if (config.isAddEarlyDataExtension()) {
                configDescription += "\nEarly Data (TLS1.3): " + Arrays.toString(config.getEarlyData());
            }
        }

        return configDescription;
    }
}
