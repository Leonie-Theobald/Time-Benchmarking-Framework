package app;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.HashAlgo;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.KeyExchangeGroup;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.TlsVersion;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
                bulkAlgo);
        if (configValidity != ConfigError.NO_ERROR) {
            throw new Error("Configuration is invalid (" + configValidity 
                + "):\n\tversion: " + version 
                + "\n\tkey ex: " + keyExchange 
                + "\n\tserver auth: " + serverAuth 
                + "\n\thash: " + hashAlgo 
                + "\n\tbulk: " + bulkAlgo);
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

        // set elliptic curve extensions
        // TODO tls13.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_ocsp_short.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_ticket-resumption_short.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_short.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_ocsp.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_ECDHE_ECDSA-SHA256_short.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_0rtt_short.config mit ECDH_X25519 hat AddECPointFormatExtension auf false
        // TODO tls13_0rtt_copy.config mit ECDH_X25519 hat AddECPointFormatExtension auf false

        // TODO tls13_DHE_ECDSA_short.config mit FFDHE2048 hat AddECPointFormatExtension auf false
        // TODO tls12_rasa_ticket-resumption_short.config RSA hat AddECPointFormatExtension auf false
        // TODO tls12_RSA_short.config RSA hat AddECPointFormatExtension auf false
        // TODO tls12_rsa_short_ocsp.config RSA hat AddECPointFormatExtension auf false
        // TODO tls12_resumption_short.config RSA hat AddECPointFormatExtension auf false
        // TODO tls12_dhe_ticket-resumption_short.config RSA hat AddECPointFormatExtension auf false
        if (keyExchange == KeyExchange.ECDHE) {
            myConfig.setAddECPointFormatExtension(true);
        } else {
            myConfig.setAddECPointFormatExtension(false);
        }

        // TODO tls12_DHE_short.config hat addEllipticCurveExtension auf false
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

        // add needed extensions
        // session resumption
        if (extensions.contains(Extension.SESSION_RESUMPTION)) {
            switch (version) {
                case TLS12:
                    myConfig.setAddSessionTicketTLSExtension(true);
                    break;            
                case TLS13:
                    List<PskKeyExchangeMode> pskList = new ArrayList<>();
                    pskList.add(PskKeyExchangeMode.PSK_KE);
                    myConfig.setPSKKeyExchangeModes(pskList);
                    myConfig.setAddPSKKeyExchangeModesExtension(true);
                    myConfig.setAddPreSharedKeyExtension(true);
                    break;
            }
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
        } else {
            myConfig.setAddCertificateStatusRequestExtension(false);
        }

        // Misc
        // TODO: tls12_resumption_short.config hat addRenegotiationInfoExtension auf true // diese Config wurde irgendwie nie verwendet
        myConfig.setAddRenegotiationInfoExtension(false);

        /*
        myConfig.setFiltersKeepUserSettings(false);
        myConfig.setDefaultServerConnection(new InboundConnection(443, "localhost"));
        myConfig.setDefaultRunningMode(RunningModeType.CLIENT);
        myConfig.setStealthMode(false);
        myConfig.setWriteKeylogFile(false);
        myConfig.setDefaultLayerConfiguration(LayerConfiguration.TLS);
        myConfig.setChooserType(ChooserType.DEFAULT);
        myConfig.setWorkflowExecutorType(WorkflowExecutorType.DEFAULT);
        myConfig.setWorkflowExecutorShouldOpen(true);
        myConfig.setWorkflowExecutorShouldClose(true);
        myConfig.setStopActionsAfterFatal(true);
        myConfig.setStopReceivingAfterFatal(true);
        myConfig.setStopActionsAfterWarning(false);
        myConfig.setStopActionsAfterIOException(true);
        myConfig.setUseFreshRandom(true);
        myConfig.setDefaultSelectedCompressionMethod(CompressionMethod.NULL);
        List<CompressionMethod> compressionList = new ArrayList<>();
        compressionList.add(CompressionMethod.NULL);
        myConfig.setDefaultClientSupportedCompressionMethods(compressionList);
        myConfig.setDefaultClientSessionId(new byte[]{});
        myConfig.setSendHandshakeMessagesWithinSingleRecord(false);
        myConfig.setDefaultMaxRecordData(16384);
        myConfig.setCreateRecordsDynamically(true);
        myConfig.setResetClientSourcePort(true);
        myConfig.setRetryFailedClientTcpSocketInitialization(false);
        myConfig.setStopTraceAfterUnexpected(false); // TODO maybe true makes more sense?
        myConfig.setFinishWithCloseNotify(false); // TODO maybe true makes more sense?
        myConfig.setReceiveFinalTcpSocketStateWithTimeout(false);
        myConfig.setResetWorkflowTracesBeforeSaving(false);
        myConfig.setDefaultServerSessionId(new byte[]{});
        myConfig.setDefaultPRFAlgorithm(PRFAlgorithm.TLS_PRF_LEGACY);
        myConfig.setPreserveMessageRecordRelation(false);

        if (keyExchange == KeyExchange.RSA) {
            // TODO FIX MODULUS
            BigInteger rsaModulus = new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "00c8820d6c3ce84c8430f6835abfc7d7a912e1664f44578751f376501a8c68476c3072d919c5d39bd0dbe080e71db83bd4ab2f2f9bde3dffb0080f510a5f6929c196551f2b3c369be051054c877573195558fd282035934dc86edab8d4b1b7f555e5b2fee7275384a756ef86cb86793b5d1333f0973203cb96966766e655cd2cccae1940e4494b8e9fb5279593b75afd0b378243e51a88f6eb88def522a8cd5c6c082286a04269a2879760fcba45005d7f2672dd228809d47274f0fe0ea5531c2bd95366c05bf69edc0f3c3189866edca0c57adcca93250ae78d9eaca0393a95ff9952fc47fb7679dd3803e6a7a6fa771861e3d99e4b551a4084668b111b7eef7d"));
            myConfig.setDefaultServerRSAModulus(rsaModulus);
            myConfig.setDefaultServerRSAPublicKey(new BigInteger("65537"));
        }

        */
        // TODO: tls12_resumption_short.config hat auch noch addCachedInfoExtension auf true // diese Config wurde nie verwendet

        System.out.println("Config:\n"
            + "\nsupported versions: " + myConfig.getSupportedVersions()
            + "\nhighest version: " + myConfig.getHighestProtocolVersion()
            + "\nSig and Hash Algos: " + myConfig.getDefaultClientSupportedSignatureAndHashAlgorithms()
            + "\nSupported Ciphers: " + myConfig.getDefaultClientSupportedCipherSuites()
        );

        /*
        File configFile = new File("");
        if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_ECDHE_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA256
                && bulkAlgo == BulkAlgo.AES_128_GCM
                && extensions.isEmpty()) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_ECDHE_RSA_SHA256_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.DHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_DHE_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.DHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.size() == 1
                && extensions.contains(Extension.SESSION_RESUMPTION)) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_dhe_ticket-resumption_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.size() == 1
                && extensions.contains(Extension.SESSION_RESUMPTION)) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_ecdhe_ticket-resumption_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.RSA
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.size() == 1
                && extensions.contains(Extension.SESSION_RESUMPTION)) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_resumption_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.RSA
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_RSA_short.config");
        } else if (version == TlsVersion.TLS13
                && keyExchange == KeyExchange.DHE
                && serverAuth == ServerAuth.ECDSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls13_DHE_ECDSA_short.config");
        } else if (version == TlsVersion.TLS13
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.ECDSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_128_GCM
                && extensions.isEmpty()) {
            configFile = new File(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls13_ECDHE_ECDSA-SHA256_short.config");
        }
        System.out.println("ConfigFile: " + configFile);
        return Config.createConfig(configFile);
        */

        return myConfig;
    }

    private enum ConfigError {
        NO_ERROR,
        TLS13_WITH_STATIC_KX,
        HASH_MISMATCHING_BULK,
    }

    public static ConfigError validateConfigCombi(
            TlsVersion version,
            KeyExchange keyExchange,
            KeyExchangeGroup keyExchangeGroup,
            ServerAuth serverAuth,
            HashAlgo hashAlgo,
            BulkAlgo bulkAlgo) {
        if (version == TlsVersion.TLS13 && keyExchange == KeyExchange.RSA
                || version == TlsVersion.TLS13 && keyExchange == KeyExchange.DH) {
            return ConfigError.TLS13_WITH_STATIC_KX;
        }

        if (bulkAlgo == BulkAlgo.AES_256_GCM && hashAlgo != HashAlgo.SHA384) {
            return ConfigError.HASH_MISMATCHING_BULK;
        }

        if (bulkAlgo == BulkAlgo.AES_128_GCM && hashAlgo != HashAlgo.SHA256) {
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

    public static NamedGroup getNamedGroup(KeyExchangeGroup keyExchangeGroup) {
        switch (keyExchangeGroup) {
            case SECP256R1:
                return NamedGroup.SECP256R1;
            case SECP384R1:
                return NamedGroup.SECP256R1;
            case SECP521R1:
                return NamedGroup.SECP256R1;
            case X25519:
                return NamedGroup.SECP256R1;
            case X448:
                return NamedGroup.SECP256R1;
            case FFDHE2048:
                return NamedGroup.SECP256R1;
            case FFDHE3072:
                return NamedGroup.SECP256R1;
            case FFDHE4096:
                return NamedGroup.SECP256R1;
            case FFDHE6144:
                return NamedGroup.SECP256R1;
            case FFDHE8192:
                return NamedGroup.SECP256R1;
             default:
                throw new Error("There is no corresponding NamedGroup for the KeyExchangeGroup: " + keyExchangeGroup);
        }
    }

    public static class CipherDetails {
        public CipherSuite cipher;
        public TlsVersion version;
        public KeyExchange keyExchange;
        public ServerAuth serverAuth;
        public BulkAlgo bulkAlgo;
        public HashAlgo hashAlgo;
        
        public CipherDetails(CipherSuite myCipher, TlsVersion myVersion, KeyExchange myKeyExchange, ServerAuth myServerAuth, BulkAlgo myBulkAlgo, HashAlgo myHashAlgo) {
            cipher = myCipher;
            version = myVersion;
            keyExchange = myKeyExchange;
            serverAuth = myServerAuth;
            bulkAlgo = myBulkAlgo;
            hashAlgo = myHashAlgo;
        }
    }

    public static CipherSuite matchCipher(TlsVersion version, KeyExchange keyExchange, ServerAuth serverAuth, BulkAlgo bulkAlgo, HashAlgo hashAlgo) {
        ArrayList<CipherDetails> ciphersOverview = new ArrayList<CipherDetails>();

        // TLS1.2 ciphers
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.RSA, ServerAuth.RSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.DHE, ServerAuth.RSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.RSA, BulkAlgo.AES_128_GCM, HashAlgo.SHA256));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.RSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        ciphersOverview.add(new CipherDetails(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TlsVersion.TLS12, KeyExchange.ECDHE, ServerAuth.ECDSA, BulkAlgo.AES_256_GCM, HashAlgo.SHA384));
        
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


}
