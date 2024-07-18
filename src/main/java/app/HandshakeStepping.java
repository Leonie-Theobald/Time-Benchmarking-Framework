package app;

import java.util.ArrayList;
import java.util.List;

import app.TimeMeasurement.StatisticResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import static de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil.getFirstSendMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;

public class HandshakeStepping {
    public enum HandshakeType {
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH,
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS12_EPHEMERAL_WITH_CLIENTAUTH,
        TLS12_STATIC_WITHOUT_CLIENTAUTH,
        TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS12_STATIC_WITH_CLIENTAUTH,
        TLS13_WITHOUT_CLIENTAUTH,
        TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
    }
    
    public static List<WorkflowTrace> getSegmentedHandshake(
            HandshakeType handshakeType,
            Config config,
            AliasedConnection connection) {

                WorkflowTrace trace = new WorkflowTrace();
                List<WorkflowTrace> segmentedHandshake = new ArrayList();

                switch (handshakeType) {
                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;
                                            
                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        // Reset connection
                        trace.addTlsAction(new ResetConnectionAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        // Second Handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;

                    case TLS12_EPHEMERAL_WITH_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        CertificateMessage certMsgEph = new CertificateMessage();
                        certMsgEph.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsgEph));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;
                    
                    case TLS12_STATIC_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;

                    case TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        // Reset connection
                        trace.addTlsAction(new ResetConnectionAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        // Second Handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;

                    case TLS12_STATIC_WITH_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        CertificateMessage certMsgStat = new CertificateMessage();
                        certMsgStat.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsgStat));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;
                            
                    case TLS13_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;

                    case TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        // remove psk extension which only needed in second handshake flow
                        HelloMessage<?> initialHello = (HelloMessage) getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO,
                            trace);
                        PreSharedKeyExtensionMessage pskExtension = initialHello.getExtension(PreSharedKeyExtensionMessage.class);
                        initialHello.getExtensions().remove(pskExtension);
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        // TODO: RFC states that SESSION_TICKET comes before FINISHED
                        // Figure 1 in https://datatracker.ietf.org/doc/html/rfc5077
                        trace.addTlsAction(new ReceiveTillAction(new NewSessionTicketMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));


                        // Second Handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;

                    default:
                        System.out.println(handshakeType + " is NOT supported.");
                        return segmentedHandshake;
                }
    }
    
    public static class StatisticResultHandshakeSegment {
        private double durationMean;
        private double durationMedian;
        private double durationStdDevMin;
        private double durationStdDevMax;
        private double durationMin;

        public static StatisticResultHandshakeSegment[] runStatisticAnalysis(StatisticResult[] statisticResultHandshake) {
            StatisticResultHandshakeSegment[] resultSegments = new StatisticResultHandshakeSegment[statisticResultHandshake.length];

            // first segment is measured against zero time
            StatisticResultHandshakeSegment firstSegment = new StatisticResultHandshakeSegment();
            firstSegment.durationMean = statisticResultHandshake[0].mean;
            firstSegment.durationMedian = statisticResultHandshake[0].median;
            firstSegment.durationStdDevMin = statisticResultHandshake[0].mean - statisticResultHandshake[0].standardDeviation;
            firstSegment.durationStdDevMax = statisticResultHandshake[0].mean + statisticResultHandshake[0].standardDeviation;
            firstSegment.durationMin = statisticResultHandshake[0].min;
            resultSegments[0] = firstSegment;

            // all other segments depend on the previous segment as well
            for (int segmentCount = 1; segmentCount < statisticResultHandshake.length; segmentCount++) {
                StatisticResultHandshakeSegment segment = new StatisticResultHandshakeSegment();
                segment.durationMean = statisticResultHandshake[segmentCount].mean - statisticResultHandshake[segmentCount-1].mean;
                segment.durationMedian = statisticResultHandshake[segmentCount].median - statisticResultHandshake[segmentCount-1].median;
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
            analysisResultsString += " Duration considering Median: " + statisticResultSegments.durationMedian/1000000.0 + " ms\n";
            analysisResultsString += " Duration Min considering StdDev: " + statisticResultSegments.durationStdDevMin/1000000.0 + " ms\n";
            analysisResultsString += " Duration Max considering StdDev: " + statisticResultSegments.durationStdDevMax/1000000.0 + " ms\n";
            analysisResultsString += " Duration considering Min: " + statisticResultSegments.durationMin/1000000.0 + " ms\n";
            
            return analysisResultsString;
        }
    }
}
