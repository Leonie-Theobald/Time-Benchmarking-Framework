package app;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.LongSummaryStatistics;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public class TimeMeasurement {
    // perform measurement for one config and one segmented handshake collection
    public static Long[][] startTimeMeasurement(
        String measurementDefinition,
        int repetition,
        Config config,
        WorkflowTrace handshakeTrace,
        int totalCntServerActions,
        Boolean shouldDocument,
        int cleanTopOutlier,
        int cleanDeviationOutlier,
        double cleanIqrOutlier
    ) {
        Long[][] durationsForServerActions = new Long[totalCntServerActions][repetition];
       
        // run repeatedly through handshake
        // collect logs of duration measurements for the different server actions
        for (int cntRep = 0; cntRep < repetition; cntRep++) {
            // results in list with [duration for 0. server action, duration for 1. server action, duration for 2. server action, ...]
            // [0. server action, 1. server action, ...]
            ArrayList<Long> collectedMeasurements = App.startTlsClient(config, handshakeTrace);

            // split list and distribute results in list bucketing all results for 0. server action, for 1. server action, ...
            // [[0. server action of 0. rep, 1. server action of 0. rep, ...], [0. server action of 0. rep, 1. server action of 0. rep, ...], ...]
            int cntServerAction = 0;
            for (Long durationOneServerAction: collectedMeasurements) {
                durationsForServerActions[cntServerAction][cntRep] = durationOneServerAction;
                cntServerAction++;
            }
        }


        // run statistical analysis on duration measurements for server actions
        StatisticResult[] statisticResultsServerActions = new StatisticResult[totalCntServerActions];
        int cntServerAction = 0;
        for (Long[] durationsForOneAction: durationsForServerActions) {
            statisticResultsServerActions[cntServerAction] = StatisticResult.runStatisticAnalysis(durationsForOneAction);
            cntServerAction++;
        }

        // check whether data should also be cleaned from outliers
        if (cleanTopOutlier > 0 || cleanDeviationOutlier > 0 || cleanIqrOutlier > 0) {
            // ## remove outliers by deleting the top end durations ##
            // calculate how many values should be removed
            int cntRemovedValues = (int) (cleanTopOutlier * repetition / 100);

            Long[][] durationsForServerActionsCleanTop = new Long[totalCntServerActions][repetition - cntRemovedValues];
            // sort each data set of the measured durations of server actions and cut the highest values
            cntServerAction = 0;
            for (Long[] durationsForOneAction: durationsForServerActions) {
                Arrays.sort(durationsForOneAction);
                List<Long> durationsList = Arrays.asList(durationsForOneAction);
                List<Long> durationsListCleanTop = durationsList.subList(0, durationsList.size() - cntRemovedValues);

                Long[] tempArray = new Long[durationsListCleanTop.size()];
                tempArray = durationsListCleanTop.toArray(tempArray);
                durationsForServerActionsCleanTop[cntServerAction] = tempArray;

                cntServerAction++;
            }

            // run statistical analysis on duration measurements for server actions
            StatisticResult[] statisticResultsServerActionsCleanTop = new StatisticResult[totalCntServerActions];
            cntServerAction = 0;
            for (Long[] durationsForOneActionCleanTop: durationsForServerActionsCleanTop) {
                statisticResultsServerActionsCleanTop[cntServerAction] = StatisticResult.runStatisticAnalysis(durationsForOneActionCleanTop);
                cntServerAction++;
            }

            
            // ## remove outliers by deleting everything with z-score above/below +/- factor ##
            ArrayList<ArrayList<Long>> durationsForServerActionsCleanDeviation = new ArrayList<>();

            // go through all durations of each server actions and only copy it if it's within the valid range
            cntServerAction = 0;
            for (Long[] durationsForOneAction: durationsForServerActions) {
                ArrayList<Long> durationsForOneActionCleanDeviation = new ArrayList<>();
                for (Long duration: durationsForOneAction) {
                    // calculate z-score
                    double zScore = (duration - statisticResultsServerActions[cntServerAction].mean) / statisticResultsServerActions[cntServerAction].standardDeviation;
                    // check whether z score lies within +/- range
                    if (zScore >= -cleanDeviationOutlier && zScore <= cleanDeviationOutlier) {
                        durationsForOneActionCleanDeviation.add(duration);
                    }
                }
                durationsForServerActionsCleanDeviation.add(durationsForOneActionCleanDeviation);
                cntServerAction++;
            }

            // run statistical analysis on duration measurements for server actions
            StatisticResult[] statisticResultsServerActionsCleanDeviation = new StatisticResult[totalCntServerActions];
            // transform ArrayList to Array
            Long[][] durationsForServerActionsCleanDeviationArray = durationsForServerActionsCleanDeviation.stream().map(u -> u.toArray(new Long[0])).toArray(Long[][]::new);
            cntServerAction = 0;
            for (Long[] durationsForOneActionCleanDeviation: durationsForServerActionsCleanDeviationArray) {
                statisticResultsServerActionsCleanDeviation[cntServerAction] = StatisticResult.runStatisticAnalysis(durationsForOneActionCleanDeviation);
                cntServerAction++;
            }


            // ## remove outliers by deleting everything outside a multiple of interquartil range (iqr) ##
            ArrayList<ArrayList<Long>> durationsForServerActionsCleanIqr = new ArrayList<>();

            // go through all durations of each server actions and only copy it if it's within the valid range
            cntServerAction = 0;
            for (Long[] durationsForOneAction: durationsForServerActions) {
                double iqr = statisticResultsServerActions[cntServerAction].quantil75 - statisticResultsServerActions[cntServerAction].quantil25;
                ArrayList<Long> durationsForOneActionCleanIqr = new ArrayList<>();
                for (Long duration: durationsForOneAction) {
                    // check whether value lies within (q_25-factor*iqr, q_75+factor*iqr) range
                    if (duration >= (statisticResultsServerActions[cntServerAction].quantil25 - cleanIqrOutlier * iqr)
                    && duration <= (statisticResultsServerActions[cntServerAction].quantil75 + cleanIqrOutlier * iqr)) {
                        durationsForOneActionCleanIqr.add(duration);
                    }
                }
                durationsForServerActionsCleanIqr.add(durationsForOneActionCleanIqr);
                cntServerAction++;
            }

            // run statistical analysis on duration measurements for server actions
            StatisticResult[] statisticResultsServerActionsCleanIqr = new StatisticResult[totalCntServerActions];
            // transform ArrayList to Array
            Long[][] durationsForServerActionsCleanIqrArray = durationsForServerActionsCleanIqr.stream().map(u -> u.toArray(new Long[0])).toArray(Long[][]::new);
            
            cntServerAction = 0;
            for (Long[] durationsForOneActionCleanIqr: durationsForServerActionsCleanIqrArray) {
                statisticResultsServerActionsCleanIqr[cntServerAction] = StatisticResult.runStatisticAnalysis(durationsForOneActionCleanIqr);
                cntServerAction++;
            }


            // log results if wished
            if (shouldDocument == true) {
                logRawAndCleanMeasurement(measurementDefinition, config, handshakeTrace, totalCntServerActions,
                    durationsForServerActions, statisticResultsServerActions, 
                    cleanTopOutlier, durationsForServerActionsCleanTop, statisticResultsServerActionsCleanTop,
                    cleanDeviationOutlier, durationsForServerActionsCleanDeviationArray, statisticResultsServerActionsCleanDeviation,
                    cleanIqrOutlier, durationsForServerActionsCleanIqrArray, statisticResultsServerActionsCleanIqr)
                ;
            }
        } else {
            // log results if wished
            if (shouldDocument == true) {
                logRawMeasurement(measurementDefinition, config, handshakeTrace, totalCntServerActions, durationsForServerActions, statisticResultsServerActions);
            }
        }

        return durationsForServerActions;
    }

    public static class StatisticResult {
        Long count;
        Long min;
        Long max;
        double mean;
        double median;
        double quantil25;
        double quantil75;
        //Long variance;
        double standardDeviation;
        double variationCoefficient;
        double skewness;
        double pearsonSkewness;
        //Long confidenceInterval95Min;
        //Long confidenceInterval95Max;
        //Long confidenceInterval99Min;
        //Long confidenceInterval99Max;


        // performs statistical analysis for one data set
        public static StatisticResult runStatisticAnalysis(Long[] dataSet) {
            StatisticResult statisticResult = new StatisticResult();

            statisticResult.count = (long)dataSet.length;

            // get few statistic values
            //new ArrayList<>(Arrays.asList(array));
            LongSummaryStatistics lss = new ArrayList<>(Arrays.asList(dataSet)).stream().mapToLong((a) -> a).summaryStatistics();
            statisticResult.min = lss.getMin();
            statisticResult.max = lss.getMax();
            statisticResult.mean = lss.getAverage();

            // get more advanced statistic values
            // Median, 25 and 75 % percentil (https://studyflix.de/statistik/quantile-1040)
            statisticResult.median = calcQuantil(dataSet, 0.5);
            statisticResult.quantil25 = calcQuantil(dataSet, 0.25);
            statisticResult.quantil75 = calcQuantil(dataSet, 0.75);

            // variance (https://studyflix.de/statistik/empirische-varianz-2016)
            double tempSum = 0.0;
            for (Long dataPoint: dataSet) {
                tempSum += (((double)dataPoint - statisticResult.mean) * ((double)dataPoint - statisticResult.mean));
            }
            double variance = tempSum / (double)(dataSet.length - 1);

            // standard deviation (https://studyflix.de/statistik/standardabweichung-1042)
            // TODO: Problem dass hier Wurzel aus double??
            statisticResult.standardDeviation = Math.sqrt(variance);

            // coefficient of variation (https://studyflix.de/statistik/variationskoeffizient-1043)
            statisticResult.variationCoefficient = statisticResult.standardDeviation / statisticResult.mean;

            // TODO: check skewness and pearson formula
            // sample skewness
            double tempSumFloat = 0.0;
            for (Long dataPoint: dataSet) {
                tempSumFloat += Math.pow(((double)dataPoint - statisticResult.mean) / statisticResult.standardDeviation, 3.0);
            }
            statisticResult.skewness = tempSumFloat * (double)dataSet.length / (double)((dataSet.length - 1) * (dataSet.length - 2));

            // pearson skewness
            statisticResult.pearsonSkewness = 3.0 * (statisticResult.mean - statisticResult.median) / statisticResult.standardDeviation;

            return statisticResult;
        }

        // helper function for quantils
        private static double calcQuantil(Long[] dataSet, Double quantil) {
            Arrays.sort(dataSet);
            
            int countDataPoints = dataSet.length;
    
            if (((countDataPoints * quantil) - (int)(countDataPoints * quantil)) == 0) {
                // number of data points times quantil is a whole number
                return (dataSet[(int)(countDataPoints * quantil - 1)] + dataSet[(int)(countDataPoints * quantil)]) / 2.0;
            } else {
                return dataSet[(int)(countDataPoints * quantil)];
            }
        }

        // creates text overview of statistical analysis
        public static String textualRepresentation(StatisticResult statisticResult) {
            String analysisResultsString = new String();

            analysisResultsString = " Elements: " + statisticResult.count + " \n";
            analysisResultsString += " Min: " + statisticResult.min/1000000.0 + " ms\n";
            analysisResultsString += " Max: " + statisticResult.max/1000000.0 + " ms\n";
            analysisResultsString += " Average: " + statisticResult.mean/1000000.0 + " ms\n";
            analysisResultsString += " Median: " + statisticResult.median/1000000.0 + " ms\n";
            analysisResultsString += " 25% Quantil: " + statisticResult.quantil25/1000000.0 + " ms\n";
            analysisResultsString += " 75% Quantil: " + statisticResult.quantil75/1000000.0 + " ms\n";
            analysisResultsString += " Std Deviation: " + statisticResult.standardDeviation/1000000.0 + " ms\n";
            analysisResultsString += " Variant Coef: " + String.format("%.3f", statisticResult.variationCoefficient*100.0) + " %\n";
            analysisResultsString += " Skewness: " + String.format("%.3f", statisticResult.skewness) + "\n";
            analysisResultsString += " Pearson's Skewness: " + String.format("%.3f", statisticResult.pearsonSkewness) + "\n";

            return analysisResultsString;
        }
    }
    
    // TODO: Add calculation of relevant server steps

    // logs raw data and statistical analysis results into file
    private static void logRawMeasurement(
        String measurementDefinition,
        Config config,
        WorkflowTrace handshakeTrace,
        int totalCntServerActions,
        Long[][] durationsForServerActions,
        StatisticResult[] statisticResultsServerActions
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
            String pathString = nowAsString;
            if (measurementDefinition != null) {
                pathString += ("_" + measurementDefinition);
            }
            pathString += ("_" + durationsForServerActions[0].length + "rep_measurement-results");

            File logFile = new File(basePath + "logging/" + pathString);

            try (PrintWriter out = new PrintWriter(logFile)) {
                out.println("TIME MEASUREMENT RESULTS\n" + nowAsString);
                
                out.println("\n\n#################################");
                out.println("Used Configuration\n");
                out.print(ConfigFactory.getConfigOverview(config));

                out.println("\n\n#################################");
                out.println("Used Handshake Trace\n");
                out.print(handshakeTrace);

                out.println("\n\n#################################");
                out.println("Used Repititions\n");
                out.print(durationsForServerActions[0].length);
                
                out.println("\n\n#################################");
                out.println("Statistic results for each server action.");
                int cntServerAction = 0;
                for (StatisticResult oneResult: statisticResultsServerActions) {
                    out.println("\nServer Action " + cntServerAction);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    cntServerAction++;
                }
                
                out.println("\n\n#################################");
                out.println("Detailed Measurement Results");
                out.print(Arrays.deepToString(durationsForServerActions));

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    // logs raw data and statistical analysis as well as the cleaned results into file
    private static void logRawAndCleanMeasurement(
        String measurementDefinition,
        Config config,
        WorkflowTrace handshakeTrace,
        int totalCntServerActions,

        Long[][] durationsForServerActions,
        StatisticResult[] statisticResultsServerActions,

        int removedTopPercentage,
        Long[][] durationsForServerActionsCleanTop,
        StatisticResult[] statisticResultsServerActionsCleanTop,

        int removedStdDevRange,
        Long[][] durationsForServerActionsCleanDeviation,
        StatisticResult[] statisticResultsServerActionsCleanDeviation,

        double removedIqrRange,
        Long[][] durationsForServerActionsCleanIqr,
        StatisticResult[] statisticResultsServerActionsCleanIqr
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
            String pathString = nowAsString;
            if (measurementDefinition != null) {
                pathString += ("_" + measurementDefinition);
            }
            pathString += ("_" + durationsForServerActions[0].length + "rep_measurement-results");

            File logFile = new File(basePath + "logging/" + pathString);

            try (PrintWriter out = new PrintWriter(logFile)) {
                out.println("TIME MEASUREMENT RESULTS\n" + nowAsString);
                
                out.println("\n\n#################################");
                out.println("Used Configuration\n");
                out.print(ConfigFactory.getConfigOverview(config));

                out.println("\n\n#################################");
                out.println("Used Handshake Trace\n");
                out.print(handshakeTrace);

                out.println("\n\n#################################");
                out.println("Used Repititions\n");
                out.print(durationsForServerActions[0].length);

                
                out.println("\n\n##################################################################");
                out.println("\n\nRAW RESULTS");
                out.println("Statistic results for each server action.");
                int cntServerAction = 0;
                for (StatisticResult oneResult: statisticResultsServerActions) {
                    out.println("\nServer Action " + cntServerAction);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    cntServerAction++;
                }


                out.println("\n\n##################################################################");
                out.println("\n\nCLEANED RESULTS (by removing top " + String.valueOf(removedTopPercentage) + "% of longest durations)");
                out.println("Statistic results cleaned by removing top durations.");
                cntServerAction = 0;
                for (StatisticResult oneResult: statisticResultsServerActionsCleanTop) {
                    out.println("\nServer Action " + cntServerAction);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    cntServerAction++;
                }
                

                out.println("\n\n##################################################################");
                out.println("\n\nCLEANED RESULTS (by removing everything with z-score above/below +/-" + String.valueOf(removedStdDevRange) + ")");
                out.println("Statistic results cleaned by removing everything outside z-score range");
                cntServerAction = 0;
                for (StatisticResult oneResult: statisticResultsServerActionsCleanDeviation) {
                    out.println("\nServer Action " + cntServerAction);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    cntServerAction++;
                }

                out.println("\n\n##################################################################");
                out.println("\n\nCLEANED RESULTS (by removing everything outside (Q_25 - " + String.valueOf(removedIqrRange) + "*IQR, Q_75 + " + String.valueOf(removedIqrRange) + "*IQR)");
                out.println("Statistic results cleaned by removing everything outside iqr range");
                cntServerAction = 0;
                for (StatisticResult oneResult: statisticResultsServerActionsCleanIqr) {
                    out.println("\nServer Action " + cntServerAction);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    cntServerAction++;
                }


                out.println("\n\n##################################################################");
                out.println("Detailed Measurement Results");

                out.println("\n\n#################################");
                out.println("Raw Detailed Measurement Results");
                out.print(Arrays.deepToString(durationsForServerActions));

                out.println("\n\n#################################");
                out.println("Top Cleaned Detailed Measurement Results");
                out.print(Arrays.deepToString(durationsForServerActionsCleanTop));

                out.println("\n\n#################################");
                out.println("Deviation Cleaned Detailed Measurement Results");
                out.print(Arrays.deepToString(durationsForServerActionsCleanDeviation));

                out.println("\n\n#################################");
                out.println("IQR Cleaned Detailed Measurement Results");
                out.print(Arrays.deepToString(durationsForServerActionsCleanIqr));

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }


        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
}