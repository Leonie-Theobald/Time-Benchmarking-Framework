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
    public static String startTimeMeasurement(
        int repetition,
        Config config,
        List<WorkflowTrace> segmentedHandshake,
        Boolean shouldDocument
    ) {
        // run repeatedly through handshake segments
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

        // Run Statistic Analysis and create report
        ArrayList<LongSummaryStatistics> analysisResults = runStatisticAnalysis(durationForHandshakeSegments);
        String analysisOverview = giveStatisticAnalysisResults(analysisResults);

        // log results if wished
        if (shouldDocument == true) {
            logMeasurement(config, segmentedHandshake, durationForHandshakeSegments, analysisResults);
        }

        return analysisOverview;
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
    }


    // performs statistical analysis for each handshake segment including all the repetitions
    public static ArrayList<LongSummaryStatistics> runStatisticAnalysis(ArrayList<ArrayList<Long>> durationForHandshakeSegments) {
        ArrayList<LongSummaryStatistics> analysisList = new ArrayList<LongSummaryStatistics>();

        for (int i=0; i<durationForHandshakeSegments.size(); i++) {
            LongSummaryStatistics lss = durationForHandshakeSegments.get(i).stream().mapToLong((a) -> a).summaryStatistics();  
            analysisList.add(lss);
        }

        // TODO: Add standard deviation, median, variance, etc.

        return analysisList;
    }
    
    // performs statistical analysis for one data set
    public static StatisticResult runStatisticAnalysisOnSingleDataset(Long[] durations) {
        StatisticResult statisticResult = new StatisticResult();

        // get few statistic values
        //new ArrayList<>(Arrays.asList(array));
        LongSummaryStatistics lss = new ArrayList<>(Arrays.asList(durations)).stream().mapToLong((a) -> a).summaryStatistics();
        statisticResult.min = lss.getMin();
        statisticResult.max = lss.getMax();
        statisticResult.mean = (long) lss.getAverage(); // rounding is fine as those numbers are in nano second range while results are only interesting in millisecond area

        // get more advanced statistic values
        // Median, 25 and 75 % percentil (https://studyflix.de/statistik/quantile-1040)
        statisticResult.median = calcQuantil(durations, 0.5);
        statisticResult.quantil25 = calcQuantil(durations, 0.25);
        statisticResult.quantil75 = calcQuantil(durations, 0.75);

        // variance (https://studyflix.de/statistik/empirische-varianz-2016)
        Long tempSum = (long)0;
        for (Long dataPoint: durations) {
            tempSum += ((dataPoint - statisticResult.mean) * (dataPoint - statisticResult.mean));
        }
        Long variance = tempSum / (durations.length - 1);

        // standard deviation (https://studyflix.de/statistik/standardabweichung-1042)
        // TODO: Problem dass hier Wurzel aus double??
        statisticResult.standardDeviation = (long) Math.sqrt(variance);

        return statisticResult;
    }

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

    // TODO: Add calculation of relevant server steps

    // creates text overview of statistical analysis
    public static String giveStatisticAnalysisResults(List<LongSummaryStatistics> analysisList) {
        int cnt = 0;
        String analysisResultsString = new String();
        analysisResultsString += "\n\nResults over " + analysisList.get(0).getCount() + " repetitions for each handshake segment.\n";

        for (LongSummaryStatistics lss: analysisList) {
            analysisResultsString += "Handshake Segment " + cnt + "\n";
            analysisResultsString += cnt + " Min: " + lss.getMin()/1000000.0 + " ms\n";
            analysisResultsString += cnt + " Max: " + lss.getMax()/1000000.0 + " ms\n";
            analysisResultsString += cnt + " Average: " + lss.getAverage()/1000000.0 + " ms\n\n";

            cnt++;
        }

        return analysisResultsString;
    }

    // logs raw data and statistical analysis results into file
    public static void logMeasurement(
        Config config,
        List<WorkflowTrace> segmentedHandshake,
        ArrayList<ArrayList<Long>> durationForHandshakeSegments,
        List<LongSummaryStatistics> analysisList
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
                out.print(getConfigOverview(config));

                out.println("\n\n#################################");
                out.println("Used Handshake Segments\n");
                out.print(segmentedHandshake);

                out.println("\n\n#################################");
                out.println("Used Repititions\n");
                out.print(analysisList.get(0).getCount());
                
                out.println("\n\n#################################");
                out.println("Anaylsis Results");
                out.print(giveStatisticAnalysisResults(analysisList));
                
                out.println("\n\n##################################################################");
                out.println("Detailled Measurement Results");
                out.print(durationForHandshakeSegments);

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }


        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    private static String getConfigOverview(Config config) {
        String configDescription = new String();

        configDescription = "Config\n";
        configDescription += "\nHighest TLS Version: " + config.getHighestProtocolVersion();
        configDescription += "\nDefault Selected Cipher Suite: " + config.getDefaultClientConnection();

        return configDescription;
    }
  
}