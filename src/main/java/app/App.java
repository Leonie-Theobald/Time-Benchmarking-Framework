package app;

import java.io.File;

import javax.swing.text.StyledEditorKit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;

public class App
{
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static void main( String[] args )
    {
        
        System.out.println( "Hello World!" );

        File configFileVar1 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short.config");
        Config var1Config = Config.createConfig(configFileVar1);
        OutboundConnection outboundConnectionVar1 = new OutboundConnection();
        outboundConnectionVar1.setHostname("localhost");
        outboundConnectionVar1.setPort(123);
        var1Config.setDefaultClientConnection(outboundConnectionVar1);
        WorkflowTrace workflowTraceVar1 = new WorkflowConfigurationFactory(var1Config).createWorkflowTrace(var1Config.getWorkflowTraceType(), RunningModeType.CLIENT);
        
        File configFileVar2 = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls13_short.config");
        Config var2Config = Config.createConfig(configFileVar2);
        OutboundConnection outboundConnectionVar2 = new OutboundConnection();
        outboundConnectionVar2.setHostname("localhost");
        outboundConnectionVar2.setPort(456);
        var2Config.setDefaultClientConnection(outboundConnectionVar2);
        WorkflowTrace workflowTraceVar2 = new WorkflowConfigurationFactory(var2Config).createWorkflowTrace(var2Config.getWorkflowTraceType(), RunningModeType.CLIENT);

        int count = 100;

        long[] arrayVar1 = new long[count];
        for (int i = 0; i < count; i++) {
            long timeElapsedVar1 = App.startTlsClient(var1Config, workflowTraceVar1);
            arrayVar1[i] = timeElapsedVar1;
            System.out.println(i + ": " + arrayVar1[i]);
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
            System.out.println(i + ": " + arrayVar2[i]);
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
        

        System.out.println("\n");
        System.out.println("Var1 average is: " + averageVar1/1000000 + " ms");
        System.out.println("Var1 min is: " + minVar1/1000000 + " ms");
        System.out.println("Var1 max is: " + maxVar1/1000000 + " ms");
        
        System.out.println("\n");
        System.out.println("Var2 average is: " + averageVar2/1000000 + " ms");
        System.out.println("Var2 min is: " + minVar2/1000000 + " ms");
        System.out.println("Var2 max is: " + maxVar2/1000000 + " ms");

        LOGGER.info("Test");
        System.out.println("test");
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
            LOGGER.warn(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
        return timeElapsed;
    }
}
