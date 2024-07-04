package app;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.SignatureScheme;
import app.ConfigurationTypes.TlsVersion;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        Config myConfig =
                ConfigFactory.getConfig(
                        TlsVersion.TLS12,
                        KeyExchange.ECDHE,
                        SignatureScheme.RSA_SHA384,
                        BulkAlgo.AES_256_GCM,
                        new Vector<Extension>());
        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        WorkflowTrace myWorkflowTrace =
                new WorkflowConfigurationFactory(myConfig)
                        .createWorkflowTrace(
                                myConfig.getWorkflowTraceType(), RunningModeType.CLIENT);

        App.startTlsClient(myConfig, myWorkflowTrace);

        System.out.println("Reached End");

        /*
        File configFileVar1 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short_forced-cipher_sig-ECDSA-SHA224.config");
        Config var1Config = Config.createConfig(configFileVar1);
        OutboundConnection outboundConnectionVar1 = new OutboundConnection();
        outboundConnectionVar1.setHostname("localhost");
        outboundConnectionVar1.setPort(123);
        var1Config.setDefaultClientConnection(outboundConnectionVar1);
        WorkflowTrace workflowTraceVar1 = new WorkflowConfigurationFactory(var1Config).createWorkflowTrace(var1Config.getWorkflowTraceType(), RunningModeType.CLIENT);

        File configFileVar2 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short_forced-cipher_sig-ECDSA-SHA256.config");
        Config var2Config = Config.createConfig(configFileVar2);
        OutboundConnection outboundConnectionVar2 = new OutboundConnection();
        outboundConnectionVar2.setHostname("localhost");
        outboundConnectionVar2.setPort(456);
        var2Config.setDefaultClientConnection(outboundConnectionVar2);
        WorkflowTrace workflowTraceVar2 = new WorkflowConfigurationFactory(var2Config).createWorkflowTrace(var2Config.getWorkflowTraceType(), RunningModeType.CLIENT);

        File configFileVar3 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short_forced-cipher_sig-ECDSA-SHA512.config");
        Config var3Config = Config.createConfig(configFileVar3);
        OutboundConnection outboundConnectionVar3 = new OutboundConnection();
        outboundConnectionVar3.setHostname("localhost");
        outboundConnectionVar3.setPort(789);
        var3Config.setDefaultClientConnection(outboundConnectionVar3);
        WorkflowTrace workflowTraceVar3 = new WorkflowConfigurationFactory(var3Config).createWorkflowTrace(var3Config.getWorkflowTraceType(), RunningModeType.CLIENT);

        int count = 200;

        long[] arrayVar1 = new long[count];
        for (int i = 0; i < count; i++) {
            long timeElapsedVar1 = App.startTlsClient(var1Config, workflowTraceVar1);
            arrayVar1[i] = timeElapsedVar1;
            //System.out.println(i + ": " + arrayVar1[i]);
        }
        long minVar1 = 999999999;
        long maxVar1 = 0;
        long sumVar1 = 0;
        for (int i = 0; i < arrayVar1.length; i++) {
            sumVar1 += arrayVar1[i];
            if (arrayVar1[i] > maxVar1) {
                maxVar1 = arrayVar1[i];
            }
            if (arrayVar1[i] < minVar1) {
                minVar1 = arrayVar1[i];
            }
        }
        long averageVar1 = sumVar1 / arrayVar1.length;

        long[] arrayVar2 = new long[count];
        for (int i = 0; i < count; i++) {
            long timeElapsedVar2 = App.startTlsClient(var2Config, workflowTraceVar2);
            arrayVar2[i] = timeElapsedVar2;
            //System.out.println(i + ": " + arrayVar2[i]);
        }
        long minVar2 = 999999999;
        long maxVar2 = 0;
        long sumVar2 = 0;
        for (int i = 0; i < arrayVar2.length; i++) {
            sumVar2 += arrayVar2[i];
            if (arrayVar2[i] > maxVar2) {
                maxVar2 = arrayVar2[i];
            }
            if (arrayVar2[i] < minVar2) {
                minVar2 = arrayVar2[i];
            }
        }
        long averageVar2 = sumVar2 / arrayVar2.length;

        long[] arrayVar3 = new long[count];
        for (int i = 0; i < count; i++) {
            long timeElapsed = App.startTlsClient(var3Config, workflowTraceVar3);
            arrayVar3[i] = timeElapsed;
            //System.out.println(i + ": " + arrayVar3[i]);
        }
        long minVar3 = 999999999;
        long maxVar3 = 0;
        long sumVar3 = 0;
        for (int i = 0; i < arrayVar3.length; i++) {
            sumVar3 += arrayVar3[i];
            if (arrayVar3[i] > maxVar3) {
                maxVar3 = arrayVar3[i];
            }
            if (arrayVar3[i] < minVar3) {
                minVar3 = arrayVar3[i];
            }
        }
        long averageVar3 = sumVar3 / arrayVar3.length;


        System.out.println("\n");
        System.out.println("Var1 average is: " + averageVar1/1000000.0 + " ms");
        System.out.println("Var1 min is: " + minVar1/1000000.0 + " ms");
        System.out.println("Var1 max is: " + maxVar1/1000000.0 + " ms");

        System.out.println("\n");
        System.out.println("Var2 average is: " + averageVar2/1000000.0 + " ms");
        System.out.println("Var2 min is: " + minVar2/1000000.0 + " ms");
        System.out.println("Var2 max is: " + maxVar2/1000000.0 + " ms");

        System.out.println("\n");
        System.out.println("Var3 average is: " + averageVar3/1000000.0 + " ms");
        System.out.println("Var3 min is: " + minVar3/1000000.0 + " ms");
        System.out.println("Var3 max is: " + maxVar3/1000000.0 + " ms");

        */

        /* NOTE on results
           File configFileVar1 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short_forced-cipher_sig-ECDSA-SHA224.config");
           Var1 average is: 4.482707 ms
           Var1 min is: 3.935625 ms
           Var1 max is: 118.931708 ms

           File configFileVar2 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short_forced-cipher_sig-ECDSA-SHA256.config");
           Var2 average is: 4.3037 ms
           Var2 min is: 3.866917 ms
           Var2 max is: 198.390584 ms

           File configFileVar3 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short_forced-cipher_sig-ECDSA-SHA512.config");
           Var3 average is: 4.147134 ms
           Var3 min is: 3.759292 ms
           Var3 max is: 11.553083 ms
        */
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
