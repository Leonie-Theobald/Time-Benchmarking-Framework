package app;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import app.ConfigurationTypes.HashAlgo;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.SignatureScheme;

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

    public enum HashAlgo {
        SHA256,
        SHA384,
    }

    public enum Extension {
        OCSP,
        ZERO_RTT,
        SESSION_RESUMPTION,
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
