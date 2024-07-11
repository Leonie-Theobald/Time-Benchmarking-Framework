package app;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import app.TimeMeasurement.StatisticResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import static de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil.getFirstSendMessage;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class HandshakeStepping {
    public enum HandshakeType {
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH,
        TLS12_STATIC_WITHOUT_CLIENTAUTH,
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS13_WITHOUT_CLIENTAUTH,
        TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
    }
    
    public static List<WorkflowTrace> getSegmentedHandshake(
            HandshakeType handshakeType,
            Config config,
            AliasedConnection connection) {

                //Vector<WorkflowTrace> segmentedHandshake = new Vector();
                WorkflowTrace trace = new WorkflowTrace();
                List<WorkflowTrace> segmentedHandshake = new ArrayList();

                switch (handshakeType) {
                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateStatusMessage()));
                        //trace.addTlsAction(new ReceiveAction(new ECDHEServerKeyExchangeMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // key exchange
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // finish
                        trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        //trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;

                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateMessage()));
                        //trace.addTlsAction(new ReceiveAction(new ECDHEServerKeyExchangeMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // key exchange
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // finish
                        trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        //trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(
                                    config,
                                    connection,
                                    ConnectionEndType.CLIENT,
                                    new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        /*
                        trace.addTlsAction(
                                MessageActionFactory.createTLSAction(
                                        config,
                                        connection,
                                        ConnectionEndType.SERVER,
                                        new ServerHelloMessage(config),
                                        new ChangeCipherSpecMessage(),
                                        new FinishedMessage()));
                        */
                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new ChChangeCipherSpecMessagea()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        /*
                        trace.addTlsAction(
                                MessageActionFactory.createTLSAction(
                                        config,
                                        connection,
                                        ConnectionEndType.CLIENT,
                                        new ChangeCipherSpecMessage(),
                                        new FinishedMessage()));
                        */
                        // finish
                        trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;
                    
                    case TLS12_STATIC_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateMessage()));
                        //trace.addTlsAction(new ReceiveAction(new ECDHEServerKeyExchangeMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // key exchange
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // finish
                        trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        //trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;

                    case TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateMessage()));
                        //trace.addTlsAction(new ReceiveAction(new ECDHEServerKeyExchangeMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // key exchange
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        // finish
                        trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        //trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(
                                    config,
                                    connection,
                                    ConnectionEndType.CLIENT,
                                    new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        /*
                        trace.addTlsAction(
                                MessageActionFactory.createTLSAction(
                                        config,
                                        connection,
                                        ConnectionEndType.SERVER,
                                        new ServerHelloMessage(config),
                                        new ChangeCipherSpecMessage(),
                                        new FinishedMessage()));
                        */
                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new ChChangeCipherSpecMessagea()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        /*
                        trace.addTlsAction(
                                MessageActionFactory.createTLSAction(
                                        config,
                                        connection,
                                        ConnectionEndType.CLIENT,
                                        new ChangeCipherSpecMessage(),
                                        new FinishedMessage()));
                        */
                        // finish
                        trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;
                            
                    case TLS13_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        // Initiation
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        //trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
                        //trace.addTlsAction(new ReceiveAction(new EncryptedExtensionsMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateMessage()));
                        //trace.addTlsAction(new ReceiveAction(new CertificateVerifyMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        List<ProtocolMessage> tls13Messages = new LinkedList<>();
                        /*
                        // would send ChangeCipherSpec
                        if (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)) {
                            ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
                            ccs.setRequired(false);
                            tls13Messages.add(ccs);
                        }
                        */
                        tls13Messages.add(new FinishedMessage());
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.CLIENT, tls13Messages));

                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;

                    case TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        
                        
                        // remove extensions only needed in second handshake flow
                        HelloMessage<?> initialHello;
                        initialHello =
                                (HelloMessage)
                                        getFirstSendMessage(
                                                HandshakeMessageType.CLIENT_HELLO, trace);
                        if (initialHello.getExtensions() != null) {
                            PreSharedKeyExtensionMessage pskExtension =
                                    initialHello.getExtension(PreSharedKeyExtensionMessage.class);
                            initialHello.getExtensions().remove(pskExtension);
                        }
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        List<ProtocolMessage> tls13MessagesResumption = new LinkedList<>();
                        tls13MessagesResumption.add(new FinishedMessage());
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.CLIENT, tls13MessagesResumption));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        MessageAction newSessionTicketAction =
                                MessageActionFactory.createTLSAction(
                                        config,
                                        connection,
                                        ConnectionEndType.SERVER,
                                        new NewSessionTicketMessage(config, false));
                        if (newSessionTicketAction instanceof ReceiveAction) {
                            newSessionTicketAction
                                    .getActionOptions()
                                    .add(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS);
                        }
                        trace.addTlsAction(newSessionTicketAction);
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        // Second Handshake
                        /*
                        List<ProtocolMessage> clientHelloMessages = new LinkedList<>();                        
                        ClientHelloMessage clientHello;
                        clientHello = new ClientHelloMessage(config);
                        clientHelloMessages.add(clientHello);
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(
                                    config, connection, ConnectionEndType.CLIENT, clientHelloMessages));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        */
                        trace.addTlsAction(
                            MessageActionFactory.createTLSAction(config, connection, ConnectionEndType.CLIENT, new ClientHelloMessage(config))
                        );
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        

                        /*
                        List<ProtocolMessage> serverMessages = new LinkedList<>();
                        FinishedMessage serverFin = new FinishedMessage();
                        
                        ServerHelloMessage serverHello;
                        serverHello = new ServerHelloMessage();
                        serverMessages.add(serverHello);
                        ChangeCipherSpecMessage ccsServer = new ChangeCipherSpecMessage();
                        ccsServer.setRequired(false);
                        if (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)) {
                            serverMessages.add(ccsServer);
                        }
                        

                        //EncryptedExtensionsMessage encExtMsg;
                        //encExtMsg = new EncryptedExtensionsMessage(config);
                        //serverMessages.add(encExtMsg);
                        serverMessages.add(serverFin);

                        trace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.SERVER, serverMessages));
                        */
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));



                        List<ProtocolMessage> clientMessages = new LinkedList<>();
                        clientMessages.add(new FinishedMessage());
                        trace.addTlsAction(
                                MessageActionFactory.createTLSAction(
                                        config, connection, ConnectionEndType.CLIENT, clientMessages));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;

                    default:
                        System.out.println(handshakeType + " is NOT supported.");
                        return segmentedHandshake;
                }
    }
    
    public static class StatisticResultHandshakeSegment {
        Long durationMean;
        Long durationStdDevMin;
        Long durationStdDevMax;
        Long durationMin;

        public static StatisticResultHandshakeSegment[] runStatisticAnalysis(StatisticResult[] statisticResultHandshake) {
            StatisticResultHandshakeSegment[] resultSegments = new StatisticResultHandshakeSegment[statisticResultHandshake.length];

            // first segment is measured against zero time
            StatisticResultHandshakeSegment firstSegment = new StatisticResultHandshakeSegment();
            firstSegment.durationMean = statisticResultHandshake[0].mean;
            firstSegment.durationStdDevMin = statisticResultHandshake[0].mean - statisticResultHandshake[0].standardDeviation;
            firstSegment.durationStdDevMax = statisticResultHandshake[0].mean + statisticResultHandshake[0].standardDeviation;
            firstSegment.durationMin = statisticResultHandshake[0].min;
            resultSegments[0] = firstSegment;

            // all other segments depend on the previous segment as well
            for (int segmentCount = 1; segmentCount < statisticResultHandshake.length; segmentCount++) {
                StatisticResultHandshakeSegment segment = new StatisticResultHandshakeSegment();
                segment.durationMean = statisticResultHandshake[segmentCount].mean - statisticResultHandshake[segmentCount-1].mean;
                segment.durationStdDevMin = (statisticResultHandshake[segmentCount].mean - statisticResultHandshake[segmentCount].standardDeviation) - (statisticResultHandshake[segmentCount-1].mean + statisticResultHandshake[segmentCount-1].standardDeviation);
                segment.durationStdDevMax = (statisticResultHandshake[segmentCount].mean + statisticResultHandshake[segmentCount].standardDeviation) - (statisticResultHandshake[segmentCount-1].mean - statisticResultHandshake[segmentCount-1].standardDeviation);
                segment.durationMin = statisticResultHandshake[segmentCount].min - statisticResultHandshake[segmentCount-1].min;
                resultSegments[segmentCount] = segment;
            }

            return resultSegments;
        }

        // creates text overview of statistical analysis
        public static String textualRepresentation(StatisticResultHandshakeSegment statisticResultSegments) {
            String analysisResultsString = " Duration considering Average: " + statisticResultSegments.durationMean/1000000.0 + " ms\n";
            analysisResultsString += " Duration Min considering StdDev: " + statisticResultSegments.durationStdDevMin/1000000.0 + " ms\n";
            analysisResultsString += " Duration Max considering StdDev: " + statisticResultSegments.durationStdDevMax/1000000.0 + " ms\n";
            analysisResultsString += " Duration considering Min: " + statisticResultSegments.durationMin/1000000.0 + " ms\n";
            
            return analysisResultsString;
        }
    }
}
