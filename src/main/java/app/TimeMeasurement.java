package app;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.Objects;
import java.util.Optional;
import java.util.Vector;
import java.util.stream.Stream;

import com.google.common.io.Files;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.TlsVersion;
import app.HandshakeStepping.HandshakeType;
import app.HandshakeStepping.StatisticResultHandshakeSegment;
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
    // perform measurement for one config and one segmented handshake collection
    public static Long[][] startTimeMeasurement(
        int repetition,
        Config config,
        List<WorkflowTrace> segmentedHandshake,
        Boolean shouldDocument
    ) {
        // run repeatedly through handshake segments
        Long[][] durationForHandshakeSegments = new Long[segmentedHandshake.size()][repetition];
            
        int segCnt = 0;
        for (WorkflowTrace partialTrace: segmentedHandshake) {
            //durationForHandshakeSegments.add(new ArrayList<Long>());

            for (int i = 0; i < repetition; i++) {
                long timeElapsed = App.startTlsClient(config, partialTrace);
                //durationForHandshakeSegments.get(segCnt).add(timeElapsed);
                durationForHandshakeSegments[segCnt][i] = timeElapsed;
            }
            segCnt++;
        }
        
        StatisticResult[] analysisListHandshake = new StatisticResult[segmentedHandshake.size()];
        segCnt = 0;
        for (Long[] dataSetOneHandshakeSegment: durationForHandshakeSegments) {
            analysisListHandshake[segCnt] = StatisticResult.runStatisticAnalysis(dataSetOneHandshakeSegment);
            segCnt++;
        }

        //StatisticResultHandshakeSegment[] analysisListSegments = new StatisticResultHandshakeSegment[segmentedHandshake.size()];
        StatisticResultHandshakeSegment[] analysisListSegments = StatisticResultHandshakeSegment.runStatisticAnalysis(analysisListHandshake);

        // log results if wished
        if (shouldDocument == true) {
            logMeasurement(config, segmentedHandshake, durationForHandshakeSegments, analysisListHandshake, analysisListSegments);
        }

        return durationForHandshakeSegments;
    }

    public static class StatisticResult {
        Long min;
        Long max;
        Long mean;
        Long median;
        Long quantil25;
        Long quantil75;
        //Long variance;
        Long standardDeviation;
        //Long confidenceInterval95Min;
        //Long confidenceInterval95Max;
        //Long confidenceInterval99Min;
        //Long confidenceInterval99Max;


        // performs statistical analysis for one data set
        public static StatisticResult runStatisticAnalysis(Long[] dataSet) {
            StatisticResult statisticResult = new StatisticResult();

            // get few statistic values
            //new ArrayList<>(Arrays.asList(array));
            LongSummaryStatistics lss = new ArrayList<>(Arrays.asList(dataSet)).stream().mapToLong((a) -> a).summaryStatistics();
            statisticResult.min = lss.getMin();
            statisticResult.max = lss.getMax();
            statisticResult.mean = (long) lss.getAverage(); // rounding is fine as those numbers are in nano second range while results are only interesting in millisecond area

            // get more advanced statistic values
            // Median, 25 and 75 % percentil (https://studyflix.de/statistik/quantile-1040)
            statisticResult.median = calcQuantil(dataSet, 0.5);
            statisticResult.quantil25 = calcQuantil(dataSet, 0.25);
            statisticResult.quantil75 = calcQuantil(dataSet, 0.75);

            // variance (https://studyflix.de/statistik/empirische-varianz-2016)
            Long tempSum = (long)0;
            for (Long dataPoint: dataSet) {
                tempSum += ((dataPoint - statisticResult.mean) * (dataPoint - statisticResult.mean));
            }
            Long variance = tempSum / (dataSet.length - 1);

            // standard deviation (https://studyflix.de/statistik/standardabweichung-1042)
            // TODO: Problem dass hier Wurzel aus double??
            statisticResult.standardDeviation = (long) Math.sqrt(variance);

            return statisticResult;
        }

        // helper function for quantils
        public static Long calcQuantil(Long[] dataSet, Double quantil) {
            //System.out.println("\nQuantil: " + quantil);
            
            //System.out.println("Unsorted Data: " + Arrays.toString(dataSet));
            Arrays.sort(dataSet);
            //System.out.println("Sorted Data: " + Arrays.toString(dataSet));
            
            int countDataPoints = dataSet.length;
            //System.out.println("Length: " + countDataPoints);
    
            if (((countDataPoints * quantil) - (int)(countDataPoints * quantil)) == 0) {
                /*
                System.out.println("if TRUE");
                System.out.println("n*p = " + countDataPoints * quantil);
                System.out.println("runtergerundet n*p = " + (int)(countDataPoints * quantil));
                System.out.println("Selected element: " + (dataSet[(int)(countDataPoints * quantil) - 1] + dataSet[(int)(countDataPoints * quantil)]) / 2);
                */
                // number of data points times quantil is a whole number
                return (dataSet[(int)(countDataPoints * quantil) - 1] + dataSet[(int)(countDataPoints * quantil)]) / 2;
            } else {
                /*
                System.out.println("if FALSE");
                System.out.println("n*p = " + countDataPoints * quantil);
                System.out.println("runtergerundet n*p = " + (int)(countDataPoints * quantil));
                System.out.println("Selected element: " + dataSet[(int)(countDataPoints * quantil)]);
                */
                return dataSet[(int)(countDataPoints * quantil)];
            }
        }

        // creates text overview of statistical analysis
        public static String textualRepresentation(StatisticResult statisticResult) {
            String analysisResultsString = new String();

            analysisResultsString = " Min: " + statisticResult.min/1000000.0 + " ms\n";
            analysisResultsString += " Max: " + statisticResult.max/1000000.0 + " ms\n";
            analysisResultsString += " Average: " + statisticResult.mean/1000000.0 + " ms\n";
            analysisResultsString += " Median: " + statisticResult.median/1000000.0 + " ms\n";
            analysisResultsString += " 25% Quantil: " + statisticResult.quantil25/1000000.0 + " ms\n";
            analysisResultsString += " 75% Quantil: " + statisticResult.quantil75/1000000.0 + " ms\n";
            analysisResultsString += " Std Deviation: " + statisticResult.standardDeviation/1000000.0 + " ms\n";

            return analysisResultsString;
        }
    }
    
    // TODO: Add calculation of relevant server steps

    // logs raw data and statistical analysis results into file
    public static void logMeasurement(
        Config config,
        List<WorkflowTrace> segmentedHandshake,
        Long[][] durationForHandshakeSegments,
        StatisticResult[] analysisListHandshake,
        StatisticResultHandshakeSegment[] analysisListSegments
    ) {
        try {
            // Get path of the JAR file and strip unnecessary folders
            String jarPath = App.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI()
                    .getPath();
            String basePath = jarPath.substring(0, jarPath.lastIndexOf("target"));
            
            Date now = Calendar.getInstance().getTime();
            String nowAsString = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss-mmmm").format(now);
            String logFileName = nowAsString + "_measurement-results";

            File logFile = new File(basePath + "logging/" + logFileName);

            try (PrintWriter out = new PrintWriter(logFile)) {
                out.println("TIME MEASUREMENT RESULTS\n" + nowAsString);
                
                out.println("\n\n#################################");
                out.println("Used Configuration\n");
                out.print(ConfigFactory.getConfigOverview(config));

                out.println("\n\n#################################");
                out.println("Used Handshake Segments\n");
                out.print(segmentedHandshake);

                out.println("\n\n#################################");
                out.println("Used Repititions\n");
                out.print(durationForHandshakeSegments[0].length);
                
                out.println("\n\n#################################");
                out.println("Results: Complete duration to the end of each handshake segment.");
                int segmentCount = 0;
                for (StatisticResult oneResult: analysisListHandshake) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    segmentCount++;
                }

                out.println("\n\n#################################");
                out.println("Results: Actual duration for each handshake segment.");
                segmentCount = 0;
                for (StatisticResultHandshakeSegment oneResult: analysisListSegments) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResultHandshakeSegment.textualRepresentation(oneResult));
                    segmentCount++;
                }
                
                out.println("\n\n##################################################################");
                out.println("Detailed Measurement Results");
                out.print(Arrays.deepToString(durationForHandshakeSegments));

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }


        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
}