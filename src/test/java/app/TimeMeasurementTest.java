package app;

import static org.junit.Assert.*;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.Test;
import app.TimeMeasurement.StatisticResult;

public class TimeMeasurementTest 
{
    @Test
    public void staticResultsDataSet0()
    {
        Long[] dataSet = { (long)300, (long)100 , (long)600, (long)100 };
        StatisticResult expectedStatisticResult = new StatisticResult();
        expectedStatisticResult.min = (long)100;
        expectedStatisticResult.max = (long)600;
        expectedStatisticResult.mean = (long)275;
        expectedStatisticResult.median = (long)200;
        expectedStatisticResult.quantil25 = (long)100;
        expectedStatisticResult.quantil75 = (long)450;
        //expectedStatisticResult.variance = (long)55833;
        expectedStatisticResult.standardDeviation = (long)236;

        StatisticResult actualStatisticResult = TimeMeasurement.runStatisticAnalysisOnSingleDataset(dataSet);

        assertThat(actualStatisticResult).usingRecursiveComparison().isEqualTo(expectedStatisticResult);
    }

    @Test
    public void staticResultsDataSet1()
    {
        Long[] dataSet = { (long)400, (long)300, (long)1000, (long)300, (long)250, (long) 178 };
        StatisticResult expectedStatisticResult = new StatisticResult();
        expectedStatisticResult.min = (long)178;
        expectedStatisticResult.max = (long)1000;
        expectedStatisticResult.mean = (long)404;
        expectedStatisticResult.median = (long)300;
        expectedStatisticResult.quantil25 = (long)250;
        expectedStatisticResult.quantil75 = (long)400;
        //expectedStatisticResult.variance = (long)90330;
        expectedStatisticResult.standardDeviation = (long)300;
        
        StatisticResult actualStatisticResult = TimeMeasurement.runStatisticAnalysisOnSingleDataset(dataSet);
        
        assertThat(actualStatisticResult).usingRecursiveComparison().isEqualTo(expectedStatisticResult);
    }

    @Test
    public void staticResultsDataSet2()
    {
        Long[] dataSet = { (long)199, (long)23, (long)4321, (long)999, (long)123 };
        StatisticResult expectedStatisticResult = new StatisticResult();
        expectedStatisticResult.min = (long)23;
        expectedStatisticResult.max = (long)4321;
        expectedStatisticResult.mean = (long)1133;
        expectedStatisticResult.median = (long)199;
        expectedStatisticResult.quantil25 = (long)123;
        expectedStatisticResult.quantil75 = (long)999;
        //expectedStatisticResult.variance = (long)3326464;
        expectedStatisticResult.standardDeviation = (long)1823;

        StatisticResult actualStatisticResult = TimeMeasurement.runStatisticAnalysisOnSingleDataset(dataSet);

        assertThat(actualStatisticResult).usingRecursiveComparison().isEqualTo(expectedStatisticResult);
    }

    @Test
    public void staticResultsDataSet3()
    {
        Long[] dataSet = { (long)430, (long)120, (long)120, (long)230, (long)630 };
        StatisticResult expectedStatisticResult = new StatisticResult();
        expectedStatisticResult.min = (long)120;
        expectedStatisticResult.max = (long)630;
        expectedStatisticResult.mean = (long)306;
        expectedStatisticResult.median = (long)230;
        expectedStatisticResult.quantil25 = (long)120;
        expectedStatisticResult.quantil75 = (long)430;
        //expectedStatisticResult.variance = (long)48830;
        expectedStatisticResult.standardDeviation = (long)220;

        StatisticResult actualStatisticResult = TimeMeasurement.runStatisticAnalysisOnSingleDataset(dataSet);

        assertThat(actualStatisticResult).usingRecursiveComparison().isEqualTo(expectedStatisticResult);
    }

    @Test
    public void staticResultsDataSet4()
    {
        Long[] dataSet = { (long)70, (long)300, (long)1200, (long)3000, (long)100, (long)200, (long)500 };
        StatisticResult expectedStatisticResult = new StatisticResult();
        expectedStatisticResult.min = (long)70;
        expectedStatisticResult.max = (long)3000;
        expectedStatisticResult.mean = (long)767;
        expectedStatisticResult.median = (long)300;
        expectedStatisticResult.quantil25 = (long)100;
        expectedStatisticResult.quantil75 = (long)1200;
        //expectedStatisticResult.variance = (long)1119223;
        expectedStatisticResult.standardDeviation = (long)1057;
        
        StatisticResult actualStatisticResult = TimeMeasurement.runStatisticAnalysisOnSingleDataset(dataSet);
        
        assertThat(actualStatisticResult).usingRecursiveComparison().isEqualTo(expectedStatisticResult);
    }
}
