package app;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

    public enum SignatureScheme {
        ECDSA_SHA384,
        ECDSA_SHA256,
        RSA_SHA384,
        RSA_SHA256,
    }

    public enum Extension {
        OCSP,
        ZERO_RTT,
        SESSION_RESUMPTION,
    }

    public enum BulkAlgo {
        AES_256_GCM,
        AES_128_GCM,
    }
}
