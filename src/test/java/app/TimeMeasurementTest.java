package app;

import org.junit.Test;

import app.TimeMeasurement.StatisticResult;

public class TimeMeasurementTest 
{
    // Notes on vector creation
    // min, max, mean, median, stddev with numbers
    // variation coef: https://www.google.com/search?client=firefox-b-d&q=kurtosis
    // skewness: https://365datascience.com/calculators/skewness-calculator/
    // pearson skewness: https://www.google.com/search?client=firefox-b-d&q=kurtosis
    // quartil: excel and own calc
    
    @Test
    public void staticResultsDataSet0()
    {
        Long[] dataSet = { (long)300, (long)100 , (long)600, (long)100 };

        StatisticResult actualStatisticResult = StatisticResult.runStatisticAnalysis(dataSet);
        
        junit.framework.Assert.assertEquals((long)100, (long)actualStatisticResult.min);
        junit.framework.Assert.assertEquals((long)600, (long)actualStatisticResult.max);
        junit.framework.Assert.assertEquals(275.0, actualStatisticResult.mean);
        junit.framework.Assert.assertEquals(236.29, Math.round(actualStatisticResult.standardDeviation*100)/100.00);
        junit.framework.Assert.assertEquals(200.0, actualStatisticResult.median);
        junit.framework.Assert.assertEquals(100.0, actualStatisticResult.quantil25);
        junit.framework.Assert.assertEquals(450.0, actualStatisticResult.quantil75);
        junit.framework.Assert.assertEquals(0.859, Math.round(actualStatisticResult.variationCoefficient*1000)/1000.0);
        junit.framework.Assert.assertEquals(1.194, Math.round(actualStatisticResult.skewness*1000)/1000.0);
        junit.framework.Assert.assertEquals(0.952, Math.round(actualStatisticResult.pearsonSkewness*1000)/1000.0);
    }

    @Test
    public void staticResultsDataSet1()
    {
        Long[] dataSet = { (long)400, (long)300, (long)1000, (long)300, (long)250, (long) 178 };

        StatisticResult actualStatisticResult = StatisticResult.runStatisticAnalysis(dataSet);
        
        junit.framework.Assert.assertEquals((long)178, (long)actualStatisticResult.min);
        junit.framework.Assert.assertEquals((long)1000, (long)actualStatisticResult.max);
        junit.framework.Assert.assertEquals(404.67, Math.round(actualStatisticResult.mean*100)/100.00);
        junit.framework.Assert.assertEquals(300.55, Math.round(actualStatisticResult.standardDeviation*100)/100.00);
        junit.framework.Assert.assertEquals(300.0, actualStatisticResult.median);
        junit.framework.Assert.assertEquals(250.0, actualStatisticResult.quantil25);
        junit.framework.Assert.assertEquals(400.0, actualStatisticResult.quantil75);
        junit.framework.Assert.assertEquals(0.743, Math.round(actualStatisticResult.variationCoefficient*1000)/1000.0);
        junit.framework.Assert.assertEquals(2.137, Math.round(actualStatisticResult.skewness*1000)/1000.0);
        junit.framework.Assert.assertEquals(1.045, Math.round(actualStatisticResult.pearsonSkewness*1000)/1000.0);
    }

    @Test
    public void staticResultsDataSet2()
    {
        Long[] dataSet = { (long)199, (long)23, (long)4321, (long)999, (long)123 };

        StatisticResult actualStatisticResult = StatisticResult.runStatisticAnalysis(dataSet);

        junit.framework.Assert.assertEquals((long)23, (long)actualStatisticResult.min);
        junit.framework.Assert.assertEquals((long)4321, (long)actualStatisticResult.max);
        junit.framework.Assert.assertEquals(1133.0, actualStatisticResult.mean);
        junit.framework.Assert.assertEquals(1823.86, Math.round(actualStatisticResult.standardDeviation*100)/100.00);
        junit.framework.Assert.assertEquals(199.0, actualStatisticResult.median);
        junit.framework.Assert.assertEquals(123.0, actualStatisticResult.quantil25);
        junit.framework.Assert.assertEquals(999.0, actualStatisticResult.quantil75);
        junit.framework.Assert.assertEquals(1.61, Math.round(actualStatisticResult.variationCoefficient*1000)/1000.0);
        junit.framework.Assert.assertEquals(2.004, Math.round(actualStatisticResult.skewness*1000)/1000.0);
        junit.framework.Assert.assertEquals(1.536, Math.round(actualStatisticResult.pearsonSkewness*1000)/1000.0);
    }

    @Test
    public void staticResultsDataSet3()
    {
        Long[] dataSet = { (long)430, (long)120, (long)120, (long)230, (long)630 };

        StatisticResult actualStatisticResult = StatisticResult.runStatisticAnalysis(dataSet);

        junit.framework.Assert.assertEquals((long)120, (long)actualStatisticResult.min);
        junit.framework.Assert.assertEquals((long)630, (long)actualStatisticResult.max);
        junit.framework.Assert.assertEquals(306.0, actualStatisticResult.mean);
        junit.framework.Assert.assertEquals(220.98, Math.round(actualStatisticResult.standardDeviation*100)/100.00);
        junit.framework.Assert.assertEquals(230.0, actualStatisticResult.median);
        junit.framework.Assert.assertEquals(120.0, actualStatisticResult.quantil25);
        junit.framework.Assert.assertEquals(430.0, actualStatisticResult.quantil75);
        junit.framework.Assert.assertEquals(0.722, Math.round(actualStatisticResult.variationCoefficient*1000)/1000.0);
        junit.framework.Assert.assertEquals(0.873, Math.round(actualStatisticResult.skewness*1000)/1000.0);
        junit.framework.Assert.assertEquals(1.032, Math.round(actualStatisticResult.pearsonSkewness*1000)/1000.0);
    }

    @Test
    public void staticResultsDataSet4()
    {
        Long[] dataSet = { (long)70, (long)300, (long)1200, (long)3000, (long)100, (long)200, (long)500 };
        
        StatisticResult actualStatisticResult = StatisticResult.runStatisticAnalysis(dataSet);
        
        junit.framework.Assert.assertEquals((long)70, (long)actualStatisticResult.min);
        junit.framework.Assert.assertEquals((long)3000, (long)actualStatisticResult.max);
        junit.framework.Assert.assertEquals(767.14, Math.round(actualStatisticResult.mean*100)/100.0);
        junit.framework.Assert.assertEquals(1057.93, Math.round(actualStatisticResult.standardDeviation*100)/100.00);
        junit.framework.Assert.assertEquals(300.0, actualStatisticResult.median);
        junit.framework.Assert.assertEquals(100.0, actualStatisticResult.quantil25);
        junit.framework.Assert.assertEquals(1200.0, actualStatisticResult.quantil75);
        junit.framework.Assert.assertEquals(1.379, Math.round(actualStatisticResult.variationCoefficient*1000)/1000.0);
        junit.framework.Assert.assertEquals(2.025, Math.round(actualStatisticResult.skewness*1000)/1000.0);
        junit.framework.Assert.assertEquals(1.325, Math.round(actualStatisticResult.pearsonSkewness*1000)/1000.0);
    }
}
