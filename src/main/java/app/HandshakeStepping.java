package app;

import java.util.ArrayList;
import java.util.List;

import app.TimeMeasurement.StatisticResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import static de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil.getFirstSendMessage;

import de.rub.nds.tlsattacker.core.workflow.action.LogLastMeasurementAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.SetMeasuringActiveAction;

public class HandshakeStepping {
    public enum HandshakeType {
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH,
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS12_EPHEMERAL_WITH_CLIENTAUTH,
        TLS12_EPHEMERAL_WITH_CLIENTAUTH_WITH_RESUMPTION,
        TLS12_STATIC_WITHOUT_CLIENTAUTH,
        TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS12_STATIC_WITH_CLIENTAUTH,
        TLS12_STATIC_WITH_CLIENTAUTH_WITH_RESUMPTION,
        TLS13_WITHOUT_CLIENTAUTH,
        TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION,
        TLS13_WITHOUT_CLIENTAUTH_WITH_ZERO_RTT,
        TLS13_WITH_CLIENTAUTH,
        TLS13_WITH_CLIENTAUTH_WITH_RESUMPTION,
    }
    
    public static List<WorkflowTrace> getSegmentedHandshake(
            HandshakeType handshakeType,
            Config config,
            AliasedConnection connection) {

                WorkflowTrace trace = new WorkflowTrace();
                List<WorkflowTrace> segmentedHandshake = new ArrayList();
                CertificateMessage certMsg = new CertificateMessage();

                switch (handshakeType) {
                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

                        //trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

                        trace.addTlsAction(new LogLastMeasurementAction());

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

                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
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

                    case TLS12_EPHEMERAL_WITH_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
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

                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
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

                    case TLS12_STATIC_WITH_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
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
                            
                    case TLS13_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

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

                    case TLS13_WITHOUT_CLIENTAUTH_WITH_ZERO_RTT:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        // remove psk extension which only needed in second handshake flow
                        HelloMessage<?> initialHello3 = (HelloMessage) getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO,
                            trace);
                        PreSharedKeyExtensionMessage pskExtension3 = initialHello3.getExtension(PreSharedKeyExtensionMessage.class);
                        EarlyDataExtensionMessage earlyDataExtension = initialHello3.getExtension(EarlyDataExtensionMessage.class);
                        initialHello3.getExtensions().remove(pskExtension3);
                        initialHello3.getExtensions().remove(earlyDataExtension);
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

                        ApplicationMessage earlyDataMessage = new ApplicationMessage();
                        earlyDataMessage.setDataConfig(config.getEarlyData());
                        trace.addTlsAction(new SendAction(earlyDataMessage));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new EndOfEarlyDataMessage()));
                        //segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        return segmentedHandshake;

                    case TLS13_WITH_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        return segmentedHandshake;

                    case TLS13_WITH_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        // remove psk extension which only needed in second handshake flow
                        HelloMessage<?> initialHello2 = (HelloMessage) getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO,
                            trace);
                        PreSharedKeyExtensionMessage pskExtension2 = initialHello2.getExtension(PreSharedKeyExtensionMessage.class);
                        initialHello2.getExtensions().remove(pskExtension2);
                        segmentedHandshake.add(WorkflowTrace.copy(trace));
                        
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
                        segmentedHandshake.add(WorkflowTrace.copy(trace));

                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
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
}
