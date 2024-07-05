package app;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Vector;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.SignatureScheme;
import app.ConfigurationTypes.TlsVersion;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class HandshakeStepping {
    public enum HandshakeType {
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH,
        TLS12_STATIC_WITHOUT_CLIENTAUTH,
        TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_SESSIONRESUMPTION,
        TLS13_WITHOUT_CLIENTAUTH,
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

                    case TLS12_EPHEMERAL_WITHOUT_CLIENTAUTH_WITH_SESSIONRESUMPTION:
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

                    default:
                        System.out.println(handshakeType + " is NOT supported.");
                        return segmentedHandshake;
                }
    }
}
