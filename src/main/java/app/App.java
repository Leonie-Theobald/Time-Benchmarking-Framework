package app;

import java.math.BigInteger;
import java.util.List;
import java.util.Vector;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.ClientAuthCert;
import app.ConfigurationTypes.ClientAuthConfig;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.KeyExchangeGroup;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.SignatureScheme;
import app.ConfigurationTypes.TlsVersion;
import app.HandshakeStepping.HandshakeType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;


public class App {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {  
        // openssl s_server -cert ./TLS-Core/src/main/resources/certs/rsa2048_rsa_cert.pem -key ./TLS-Core/src/main/resources/certs/rsa2048_key.pem -tls1_2 -Verify 3 -CAfile ./Zusatzzeug/keyGen/rsa2048_cert.pem -trace
        CustomRSAPrivateKey privKey = new CustomRSAPrivateKey(
            new BigInteger("22680894355213276814068604237379515326692913667424423179105887452289906651381282343803736135056197131595363416117766447222033440405148554595150495098954618784791409846721078014631997901600818192748951260294724453863786822963457535714201456929910107294028887630816463336166663178044202436591458723765695469483323295740091515251848862253753967572511917223940594872506608243732478287780716299338656301737923256700355562820768458403307832462075060029877854803131864443444034500618089480396072963994147799521776599695622459322293973138939514112920721100797951815691387710738229293066991665386400046197146008454129381303013"),
            new BigInteger("1081220900519306994054118481314527476163106719322647452617727838882406914114781299588271417902671126167388106236144671423388446493562843049877263993876061364494202266642979463380542895308994686679330955004731190982136777534172265998708970859053814947427221608823239751002807226391716969448091277902763492530629102587274894712676589402812658549391491035698540223575850258784236700772902034492790099278379171982874885903225435518252664651224422790750083966520867503120878596752239393242686207324374684442156551897779979099846701806053546967178413553042480432389633260063913612546788291398650159971518641894650833502207"));
        
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    ClientAuthCert.RSA,
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/keyGen/rsa2048_cert.pem",
                    privKey
        );
        /*
        //EC Certificate
        byte[] derEncdoedPrivKey = new byte[]{(byte)0x04, (byte)0x30, (byte)0xE3, (byte)0x17, (byte)0x0C, (byte)0x60, (byte)0xC7, (byte)0x2E, (byte)0x6F, (byte)0xDD, (byte)0x09, (byte)0x89, (byte)0x5F, (byte)0xAA, (byte)0x26, (byte)0xED, (byte)0x2F, (byte)0x58, (byte)0x72, (byte)0x99, (byte)0xA7, (byte)0xA8, (byte)0x17, (byte)0x0A, (byte)0x2A, (byte)0x6D, (byte)0xED, (byte)0x23, (byte)0x89, (byte)0x84, (byte)0x8A, (byte)0xF7, (byte)0xCB, (byte)0xBF, (byte)0xA8, (byte)0x2C, (byte)0xED, (byte)0x84, (byte)0xBE, (byte)0x99, (byte)0x15, (byte)0xB3, (byte)0xDF, (byte)0x62, (byte)0x93, (byte)0xD5, (byte)0x3D, (byte)0x55, (byte)0xC3, (byte)0x25};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP384R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    ClientAuthCert.ECDSA,
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/keyGen/ec_secp384r1_cert.pem",
                    privKey
        );
        */

        Config myConfig =
            ConfigFactory.getConfig(
                TlsVersion.TLS12,
                KeyExchange.RSA,
                KeyExchangeGroup.NONE,
                ServerAuth.RSA,
                clientAuthConfig,
                new Vector<SignatureScheme>(){{add(SignatureScheme.RSA_SHA384);add(SignatureScheme.ECDSA_SHA384);}},
                BulkAlgo.AES_256_GCM_SHA384,
                new Vector<Extension>(){{add(Extension.RESUMPTION_SESSION_TICKET);}});
                //new Vector<>());

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS12_STATIC_WITH_CLIENTAUTH_WITH_RESUMPTION, myConfig, outboundCon);
        Long[][] resultsMeasurement = TimeMeasurement.startTimeMeasurement(3, myConfig, segmentedHandshake, true, 1, 3, 1.5);
        //System.out.println(resultsMeasurement);

        System.out.println("Reached End");
    }

    public static long startTlsClient(Config config, WorkflowTrace trace) {
        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);

        long timeElapsed = 0;
        try {
            long start = System.nanoTime();
            workflowExecutor.executeWorkflow();
            long finish = System.nanoTime();
            timeElapsed = finish - start;
        } catch (WorkflowExecutionException ex) {
            System.out.println(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.warn(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
        }
        return timeElapsed;
    }
}
