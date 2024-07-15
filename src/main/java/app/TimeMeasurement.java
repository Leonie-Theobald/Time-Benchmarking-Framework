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

import app.HandshakeStepping.StatisticResultHandshakeSegment;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public class TimeMeasurement {
    // perform measurement for one config and one segmented handshake collection
    public static Long[][] startTimeMeasurement(
        int repetition,
        Config config,
        List<WorkflowTrace> segmentedHandshake,
        Boolean shouldDocument,
        int cleanTopOutlier,
        int cleanDeviationOutlier
    ) {
        // run repeatedly through handshake segments
        Long[][] durationForHandshakeSegments = new Long[segmentedHandshake.size()][repetition];
            
        int segCnt = 0;
        for (WorkflowTrace partialTrace: segmentedHandshake) {
            for (int i = 0; i < repetition; i++) {
                long timeElapsed = App.startTlsClient(config, partialTrace);
                durationForHandshakeSegments[segCnt][i] = timeElapsed;
            }
            segCnt++;
        }

        // run statistical analysis
        // for the data set of each handshake segment (always measured from 0.00ms to end of handshake segment)
        StatisticResult[] analysisListHandshake = new StatisticResult[segmentedHandshake.size()];
        segCnt = 0;
        for (Long[] dataSetOneHandshakeSegment: durationForHandshakeSegments) {
            analysisListHandshake[segCnt] = StatisticResult.runStatisticAnalysis(dataSetOneHandshakeSegment);
            segCnt++;
        }
        // statistical analysis for each handshake segment on its own (measured from previous to own handshake segment)
        StatisticResultHandshakeSegment[] analysisListSegments = StatisticResultHandshakeSegment.runStatisticAnalysis(analysisListHandshake);

        // check whether data should also be cleaned from outliers
        if (cleanTopOutlier > 0 || cleanDeviationOutlier > 0) {
            // ## remove outliers by deleting the top end durations ##
            // calculate how many values should be removed
            int cntRemovedValues = (int) (cleanTopOutlier * repetition / 100);

            Long[][] durationForHandshakeSegmentsTopClean = new Long[segmentedHandshake.size()][repetition  - cntRemovedValues];
            // sort each data set of the handshake and cut the highest values
            segCnt = 0;
            for (Long[] segment: durationForHandshakeSegments) {
                Arrays.sort(segment);
                List<Long> segmentList = Arrays.asList(segment);
                List<Long> segmentListTopClean = segmentList.subList(0, segmentList.size() - cntRemovedValues);

                Long[] tempArray = new Long[segmentList.size() - cntRemovedValues];
                tempArray = segmentListTopClean.toArray(tempArray);
                durationForHandshakeSegmentsTopClean[segCnt] = tempArray;

                segCnt++;
            }

            // do same analysis steps as for raw data
            StatisticResult[] analysisListHandshakeTopClean = new StatisticResult[segmentedHandshake.size()];
            segCnt = 0;
            for (Long[] dataSetOneHandshakeSegmenTopClean: durationForHandshakeSegmentsTopClean) {
                analysisListHandshakeTopClean[segCnt] = StatisticResult.runStatisticAnalysis(dataSetOneHandshakeSegmenTopClean);
                segCnt++;
            }
            // statistical analysis for each handshake segment on its own (measured from previous to own handshake segment)
            StatisticResultHandshakeSegment[] analysisListSegmentsTopClean = StatisticResultHandshakeSegment.runStatisticAnalysis(analysisListHandshakeTopClean);

            // ## remove outliers by deleting everything outside a multiple of standard deviation ##
            ArrayList<ArrayList<Long>> durationForHandshakeSegmentsDeviationClean = new ArrayList<>();
            // go through each element for each handshake segment and only copy it if it's within the valid range
            segCnt = 0;
            for (Long[] segment: durationForHandshakeSegments) {
                ArrayList<Long> segmentClean = new ArrayList<>();
                for (Long val: segment) {
                    // check whether value lies within avg +- cleanDeviationOutlier*stddev range
                    if (val >= (analysisListHandshake[segCnt].mean - cleanDeviationOutlier * analysisListHandshake[segCnt].standardDeviation)
                    && val <= (analysisListHandshake[segCnt].mean + cleanDeviationOutlier * analysisListHandshake[segCnt].standardDeviation)) {
                        segmentClean.add(val);
                    }
                }
                durationForHandshakeSegmentsDeviationClean.add(segmentClean);
                segCnt++;
            }

            // transform ArrayList to Array
            Long[][] durationForHandshakeSegmentsDeviationCleanArray = durationForHandshakeSegmentsDeviationClean.stream().map(u -> u.toArray(new Long[0])).toArray(Long[][]::new);

            // do same analysis steps as for raw data
            StatisticResult[] analysisListHandshakeDeviationClean = new StatisticResult[segmentedHandshake.size()];
            segCnt = 0;
            for (Long[] dataSetOneHandshakeSegmentDeviationClean: durationForHandshakeSegmentsDeviationCleanArray) {
                analysisListHandshakeDeviationClean[segCnt] = StatisticResult.runStatisticAnalysis(dataSetOneHandshakeSegmentDeviationClean);
                segCnt++;
            }
            // statistical analysis for each handshake segment on its own (measured from previous to own handshake segment)
            StatisticResultHandshakeSegment[] analysisListSegmentsDeviationClean = StatisticResultHandshakeSegment.runStatisticAnalysis(analysisListHandshakeDeviationClean);

            // log results if wished
            if (shouldDocument == true) {
                logRawAndCleanMeasurement(config, segmentedHandshake, durationForHandshakeSegments, analysisListHandshake, analysisListSegments, cleanTopOutlier, durationForHandshakeSegmentsTopClean, analysisListHandshakeTopClean, analysisListSegmentsTopClean, cleanDeviationOutlier, durationForHandshakeSegmentsDeviationCleanArray, analysisListHandshakeDeviationClean, analysisListSegmentsDeviationClean);
            }
        } else {
            // log results if wished
            if (shouldDocument == true) {
                logRawMeasurement(config, segmentedHandshake, durationForHandshakeSegments, analysisListHandshake, analysisListSegments);
            }
        }

        return durationForHandshakeSegments;
    }

    public static class StatisticResult {
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

            analysisResultsString = " Min: " + statisticResult.min/1000000.0 + " ms\n";
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
                
                out.println("\n\n#################################");
                out.println("Detailed Measurement Results");
                out.print(Arrays.deepToString(durationForHandshakeSegments));

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }


        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    // logs raw data and statistical analysis as well as the cleaned results into file
    private static void logRawAndCleanMeasurement(
        Config config,
        List<WorkflowTrace> segmentedHandshake,
        Long[][] durationForHandshakeSegmentsRaw,
        StatisticResult[] analysisListHandshakeRaw,
        StatisticResultHandshakeSegment[] analysisListSegmentsRaw,

        int removedTopPercentage,
        Long[][] durationForHandshakeSegmentsTopClean,
        StatisticResult[] analysisListHandshakeTopClean,
        StatisticResultHandshakeSegment[] analysisListSegmentsTopClean,

        int removedStdDevRange,
        Long[][] durationForHandshakeSegmentsDeviationClean,
        StatisticResult[] analysisListHandshakeDeviationClean,
        StatisticResultHandshakeSegment[] analysisListSegmentsDeviationClean
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
                out.print(durationForHandshakeSegmentsRaw[0].length);

                
                out.println("\n\n##################################################################");
                out.println("\n\nRAW RESULTS");
            
                out.println("\n\n#################################");
                out.println("Raw Results: Complete duration to the end of each handshake segment.");
                int segmentCount = 0;
                for (StatisticResult oneResult: analysisListHandshakeRaw) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    segmentCount++;
                }

                out.println("\n\n#################################");
                out.println("Raw Results: Actual duration for each handshake segment.");
                segmentCount = 0;
                for (StatisticResultHandshakeSegment oneResult: analysisListSegmentsRaw) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResultHandshakeSegment.textualRepresentation(oneResult));
                    segmentCount++;
                }


                out.println("\n\n##################################################################");
                out.println("\n\nCLEANED RESULTS (by removing top " + String.valueOf(removedTopPercentage) + "% of longest durations)");
            
                out.println("\n\n#################################");
                out.println("Cleaned Results (top removal): Complete duration to the end of each handshake segment.");
                segmentCount = 0;
                for (StatisticResult oneResult: analysisListHandshakeTopClean) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    segmentCount++;
                }

                out.println("\n\n#################################");
                out.println("Cleaned Results (top removal): Actual duration for each handshake segment.");
                segmentCount = 0;
                for (StatisticResultHandshakeSegment oneResult: analysisListSegmentsTopClean) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResultHandshakeSegment.textualRepresentation(oneResult));
                    segmentCount++;
                }
                

                out.println("\n\n##################################################################");
                out.println("\n\nCLEANED RESULTS (by removing everything outside " + String.valueOf(removedStdDevRange) + " +/- stddev the average)");
            
                out.println("\n\n#################################");
                out.println("Cleaned Results (deviation): Complete duration to the end of each handshake segment.");
                segmentCount = 0;
                for (StatisticResult oneResult: analysisListHandshakeDeviationClean) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResult.textualRepresentation(oneResult));
                    segmentCount++;
                }

                out.println("\n\n#################################");
                out.println("Cleaned Results (deviation): Actual duration for each handshake segment.");
                segmentCount = 0;
                for (StatisticResultHandshakeSegment oneResult: analysisListSegmentsDeviationClean) {
                    out.println("\nHandshake Segment " + segmentCount);
                    out.print(StatisticResultHandshakeSegment.textualRepresentation(oneResult));
                    segmentCount++;
                }


                out.println("\n\n##################################################################");
                out.println("Detailed Measurement Results");

                out.println("\n\n#################################");
                out.println("Raw Detailed Measurement Results");
                out.print(Arrays.deepToString(durationForHandshakeSegmentsRaw));

                out.println("\n\n#################################");
                out.println("Top Cleaned Detailed Measurement Results");
                out.print(Arrays.deepToString(durationForHandshakeSegmentsTopClean));

                out.println("\n\n#################################");
                out.println("Deviation Cleaned Detailed Measurement Results");
                out.print(Arrays.deepToString(durationForHandshakeSegmentsDeviationClean));

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }


        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
}