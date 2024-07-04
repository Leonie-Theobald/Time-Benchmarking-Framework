package app;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.LongSummaryStatistics;
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
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class TimeMeasurement {    
    public static ArrayList<ArrayList<Long>> startTimeMeasurement(
        int repetition,
        Config config,
        List<WorkflowTrace> segmentedHandshake
    ) {
        ArrayList<ArrayList<Long>> durationForHandshakeSegments = new ArrayList<ArrayList<Long>>();
            
        int segCnt = 0;
        for (WorkflowTrace partialTrace: segmentedHandshake) {   
            durationForHandshakeSegments.add(new ArrayList<Long>());

            for (int i = 0; i < repetition; i++) {
                long timeElapsed = App.startTlsClient(config, partialTrace);
                durationForHandshakeSegments.get(segCnt).add(timeElapsed);
            }
            segCnt++;
        }

        return durationForHandshakeSegments;
    }

    public static ArrayList<LongSummaryStatistics> runStatisticAnalysis(ArrayList<ArrayList<Long>> durationForHandshakeSegments) {
        ArrayList<LongSummaryStatistics> analysisList = new ArrayList<LongSummaryStatistics>();

        for (int i=0; i<durationForHandshakeSegments.size(); i++) {
            LongSummaryStatistics lss = durationForHandshakeSegments.get(i).stream().mapToLong((a) -> a).summaryStatistics();  
            analysisList.add(lss);
        }

        return analysisList;
    }

    public static void printStatisticAnalysisResults(List<LongSummaryStatistics> analysisList) {
        int cnt = 0;
        for (LongSummaryStatistics lss: analysisList) {
            System.out.println("\n");

            System.out.println(cnt + " Min: " + lss.getMin()/1000000.0 + " ms");
            System.out.println(cnt + " Max: " + lss.getMax()/1000000.0 + " ms");
            System.out.println(cnt + " Average: " + lss.getAverage()/1000000.0 + " ms");  

            cnt++;
        }
    }
}
