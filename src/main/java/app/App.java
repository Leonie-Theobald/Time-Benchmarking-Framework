package app;

import java.io.File;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;

public class App
{
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static void main( String[] args )
    {
        
        System.out.println( "Hello World!" );
        File configFile = new File("/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/tls12_short.config");
        Config tls12Config = Config.createConfig(configFile);
    
        WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(tls12Config).createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);

        State state = App.startTlsClient(tls12Config, workflowTrace);
        LOGGER.info("Test");
    }

    public static State startTlsClient(Config config, WorkflowTrace trace) {
        State state;
        if (trace == null) {
            state = new State(config);
        } else {
            state = new State(config, trace);
        }
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);
        try {
            workflowExecutor.executeWorkflow();
            LOGGER.info("Workflow finished.");
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
        return state;
    }
}
