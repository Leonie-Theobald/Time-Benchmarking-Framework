package app;

import java.util.ArrayList;
import java.util.List;

import app.HandshakeTypes.HandshakeType;
import app.TimeMeasurement.StatisticResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
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

public class HandshakeActions {

    private int serverCntActions;
    private WorkflowTrace trace;

    public int getCntServerActions() {
        return this.serverCntActions;
    }
    public WorkflowTrace getTrace() {
        return this.trace;
    }
    
    public HandshakeActions (
            HandshakeType handshakeType,
            Config config,
            AliasedConnection connection) {

                WorkflowTrace trace = new WorkflowTrace();
                CertificateMessage certMsg = new CertificateMessage();

                switch (handshakeType) {
                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        this.trace = trace;
                        this.serverCntActions = 2;
                        break;

                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        // Reset connection
                        trace.addTlsAction(new ResetConnectionAction());
                        
                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;

                    case TLS12_EPHEMERAL_WITH_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(certMsg));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        this.trace = trace;
                        this.serverCntActions = 2;
                        break;

                    case TLS12_EPHEMERAL_WITH_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(certMsg));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        // Reset connection
                        trace.addTlsAction(new ResetConnectionAction());

                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;
                    
                    case TLS12_STATIC_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        this.trace = trace;
                        this.serverCntActions = 2;
                        break;

                    case TLS12_STATIC_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        // Reset connection
                        trace.addTlsAction(new ResetConnectionAction());
                        
                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;

                    case TLS12_STATIC_WITH_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(certMsg));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        this.trace = trace;
                        this.serverCntActions = 2;
                        break;

                    case TLS12_STATIC_WITH_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(certMsg));
                        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        // Reset connection
                        trace.addTlsAction(new ResetConnectionAction());

                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;
                            
                    case TLS13_WITHOUT_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 1;
                        break;

                    case TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // first handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        // remove psk extension which only needed in second handshake flow
                        HelloMessage<?> initialHello = (HelloMessage) getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO,
                            trace);
                        PreSharedKeyExtensionMessage pskExtension = initialHello.getExtension(PreSharedKeyExtensionMessage.class);
                        initialHello.getExtensions().remove(pskExtension);
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        // TODO: RFC states that SESSION_TICKET comes before FINISHED
                        // Figure 1 in https://datatracker.ietf.org/doc/html/rfc5077
                        trace.addTlsAction(new ReceiveTillAction(new NewSessionTicketMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());

                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;

                    case TLS13_WITHOUT_CLIENTAUTH_WITH_ZERO_RTT:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        // remove psk extension which only needed in second handshake flow
                        HelloMessage<?> initialHello3 = (HelloMessage) getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO,
                            trace);
                        PreSharedKeyExtensionMessage pskExtension3 = initialHello3.getExtension(PreSharedKeyExtensionMessage.class);
                        EarlyDataExtensionMessage earlyDataExtension = initialHello3.getExtension(EarlyDataExtensionMessage.class);
                        initialHello3.getExtensions().remove(pskExtension3);
                        initialHello3.getExtensions().remove(earlyDataExtension);
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());
                        
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        // TODO: RFC states that SESSION_TICKET comes before FINISHED
                        // Figure 1 in https://datatracker.ietf.org/doc/html/rfc5077
                        trace.addTlsAction(new ReceiveTillAction(new NewSessionTicketMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());

                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        ApplicationMessage earlyDataMessage = new ApplicationMessage();
                        earlyDataMessage.setDataConfig(config.getEarlyData());
                        trace.addTlsAction(new SendAction(earlyDataMessage));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;

                    case TLS13_WITH_CLIENTAUTH:
                        System.out.println(handshakeType + " is supported.");

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 1;
                        break;

                    case TLS13_WITH_CLIENTAUTH_WITH_RESUMPTION:
                        System.out.println(handshakeType + " is supported.");

                        // First handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        // remove psk extension which only needed in second handshake flow
                        HelloMessage<?> initialHello2 = (HelloMessage) getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO,
                            trace);
                        PreSharedKeyExtensionMessage pskExtension2 = initialHello2.getExtension(PreSharedKeyExtensionMessage.class);
                        initialHello2.getExtensions().remove(pskExtension2);
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        certMsg = new CertificateMessage();
                        certMsg.setCertificateKeyPair(config.getDefaultExplicitCertificateKeyPair());
                        trace.addTlsAction(new SendAction(certMsg));
                        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));

                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        // TODO: RFC states that SESSION_TICKET comes before FINISHED
                        // Figure 1 in https://datatracker.ietf.org/doc/html/rfc5077
                        trace.addTlsAction(new ReceiveTillAction(new NewSessionTicketMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        // Reset connection and start with session resumption
                        trace.addTlsAction(new ResetConnectionAction());

                        // Second Handshake
                        trace.addTlsAction(new SetMeasuringActiveAction(true));
                        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
                        trace.addTlsAction(new LogLastMeasurementAction());

                        trace.addTlsAction(new SetMeasuringActiveAction(false));
                        trace.addTlsAction(new SendAction(new FinishedMessage()));
                        
                        this.trace = trace;
                        this.serverCntActions = 3;
                        break;
 
                    default:
                        System.out.println(handshakeType + " is NOT supported.");
                        //return segmentedHandshake;
                }
    }
}
