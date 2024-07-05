package app;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.HashAlgo;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.TlsVersion;
import de.rub.nds.tlsattacker.core.config.Config;
import java.io.File;
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConfigFactory {
    private static final Logger LOGGER = LogManager.getLogger();

    public static Config getConfig(
            TlsVersion version,
            KeyExchange keyExchange,
            ServerAuth serverAuth,
            HashAlgo hashAlgo,
            BulkAlgo bulkAlgo,
            Vector<Extension> extensions) {

        ConfigError configValidity = validateConfigCombi(
            version,
            keyExchange,
            serverAuth,
            hashAlgo,
            bulkAlgo);
        if (configValidity != ConfigError.NO_ERROR) {
                throw new Error("Configuration is invalid (" + configValidity + "):\n\tversion: " + version + "\n\tkey ex: " + keyExchange + "\n\tserver auth: " + serverAuth + "\n\thash: " + hashAlgo + "\n\tbulk: " + bulkAlgo);
            }

        File configFile = new File("");

        if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_ECDHE_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA256
                && bulkAlgo == BulkAlgo.AES_128_GCM
                && extensions.isEmpty()) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_ECDHE_RSA_SHA256_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.DHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_DHE_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.DHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.size() == 1
                && extensions.contains(Extension.SESSION_RESUMPTION)) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_dhe_ticket-resumption_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.size() == 1
                && extensions.contains(Extension.SESSION_RESUMPTION)) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_ecdhe_ticket-resumption_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.RSA
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.size() == 1
                && extensions.contains(Extension.SESSION_RESUMPTION)) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_resumption_short.config");
        } else if (version == TlsVersion.TLS12
                && keyExchange == KeyExchange.RSA
                && serverAuth == ServerAuth.RSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_RSA_short.config");
        } else if (version == TlsVersion.TLS13
                && keyExchange == KeyExchange.DHE
                && serverAuth == ServerAuth.ECDSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_256_GCM
                && extensions.isEmpty()) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls13_DHE_ECDSA_short.config");
        } else if (version == TlsVersion.TLS13
                && keyExchange == KeyExchange.ECDHE
                && serverAuth == ServerAuth.ECDSA
                && hashAlgo == HashAlgo.SHA384
                && bulkAlgo == BulkAlgo.AES_128_GCM
                && extensions.isEmpty()) {
            configFile =
                    new File(
                            "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls13_ECDHE_ECDSA-SHA256_short.config");
        }

        System.out.println("ConfigFile: " + configFile);
        return Config.createConfig(configFile);
    }

    private enum ConfigError {
        NO_ERROR,
        TLS13_WITH_STATIC_KX,
        HASH_MISMATCHING_BULK,
    }

    public static ConfigError validateConfigCombi(
        TlsVersion version,
        KeyExchange keyExchange,
        ServerAuth serverAuth,
        HashAlgo hashAlgo,
        BulkAlgo bulkAlgo
    ) {
        if (
            version == TlsVersion.TLS13 && keyExchange == KeyExchange.RSA
            || version == TlsVersion.TLS13 && keyExchange == KeyExchange.DH) {
                return ConfigError.TLS13_WITH_STATIC_KX;
            }
        
        if (
            bulkAlgo == BulkAlgo.AES_256_GCM && hashAlgo != HashAlgo.SHA384) {
                return ConfigError.HASH_MISMATCHING_BULK;
            }

        if (
            bulkAlgo == BulkAlgo.AES_128_GCM && hashAlgo != HashAlgo.SHA256) {
                return ConfigError.HASH_MISMATCHING_BULK;
            }

        return ConfigError.NO_ERROR;
    }
}


