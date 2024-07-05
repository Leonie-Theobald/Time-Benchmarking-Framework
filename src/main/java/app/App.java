package app;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.HashAlgo;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.TlsVersion;
import app.HandshakeStepping;
import app.HandshakeStepping.HandshakeType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        /*
        Config myConfigEllipticCurve =
            ConfigFactory.getConfig(
                TlsVersion.TLS12,
                KeyExchange.ECDHE,
                SignatureScheme.RSA_SHA384,
                BulkAlgo.AES_256_GCM,
                new Vector<Extension>());

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfigEllipticCurve.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH, myConfigEllipticCurve, outboundCon);
        */

        /*
        Config myConfig =
            ConfigFactory.getConfig(
                TlsVersion.TLS12,
                KeyExchange.RSA,
                SignatureScheme.RSA_SHA384,
                BulkAlgo.AES_256_GCM,
                new Vector<Extension>());

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS12_STATIC_WITHOUT_CLIENTAUTH, myConfig, outboundCon);
        */

        /*
        Config myConfig =
            ConfigFactory.getConfig(
                TlsVersion.TLS13,
                KeyExchange.DHE,
                SignatureScheme.ECDSA_SHA384,
                BulkAlgo.AES_256_GCM,
                new Vector<Extension>());

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS13_WITHOUT_CLIENTAUTH, myConfig, outboundCon);
        */
        
        /*
        Config myConfig =
            ConfigFactory.getConfig(
                TlsVersion.TLS12,
                KeyExchange.ECDHE,
                SignatureScheme.RSA_SHA384,
                BulkAlgo.AES_256_GCM,
                new Vector<Extension>(){{add(Extension.SESSION_RESUMPTION);}});

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_SESSIONRESUMPTION, myConfig, outboundCon);
        */

        Config myConfig =
            ConfigFactory.getConfig(
                TlsVersion.TLS12,
                KeyExchange.RSA,
                ServerAuth.RSA,
                HashAlgo.SHA384,
                BulkAlgo.AES_256_GCM,
                new Vector<Extension>(){{add(Extension.SESSION_RESUMPTION);}});

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_SESSIONRESUMPTION, myConfig, outboundCon);

        String resultsMeasurement = TimeMeasurement.startTimeMeasurement(2, myConfig, segmentedHandshake, true);
        System.out.println(resultsMeasurement);

        System.out.println("Reached End");
    }

    public static long startTlsClient(Config config, WorkflowTrace trace) {
        /*State state;
        if (trace == null) {
            state = new State(config);
        } else {
            state = new State(config, trace);
        }*/
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
            // LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
        return timeElapsed;
    }
}
