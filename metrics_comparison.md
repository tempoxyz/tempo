# Tempo Benchmark Comparison

Main commit: ``debug_main.log``
Feature commit: ``debug_feature.log``

| Metric | Statistic | Main | Feature | Abs Diff | % Change |
| --- | --- | --- | --- | --- | --- |
| Build Payload Time | Average | 352.368 ms | 318.035 ms | -34.333 ms | -9.7% |
|  | Median | 309.861 ms | 318.483 ms | +8.622 ms | +2.8% |
|  | Min | 252.534 ms | 240.773 ms | -11.761 ms | -4.7% |
|  | Max | 578.119 ms | 404.723 ms | -173.396 ms | -30.0% |
|  | Std Dev | 99.065 ms | 48.856 ms | -50.209 ms | -50.7% |
| Payload Delivery Lag | Average | 6.680 ms | 4.594 ms | -2.085 ms | -31.2% |
|  | Median | 4.842 ms | 4.399 ms | -0.443 ms | -9.2% |
|  | Min | 2.892 ms | 2.940 ms | +0.048 ms | +1.7% |
|  | Max | 25.717 ms | 6.628 ms | -19.089 ms | -74.2% |
|  | Std Dev | 6.736 ms | 1.115 ms | -5.621 ms | -83.5% |
| Explicit State Root Task | Average | 9.794 ms | 8.496 ms | -1.299 ms | -13.3% |
|  | Median | 5.023 ms | 4.473 ms | -0.550 ms | -11.0% |
|  | Min | 0.004 ms | 0.004 ms | +0.000 ms | +5.7% |
|  | Max | 83.490 ms | 63.391 ms | -20.098 ms | -24.1% |
|  | Std Dev | 13.393 ms | 9.773 ms | -3.619 ms | -27.0% |
| Block Added to Canonical Chain | Average | 2069.473 ms | 2003.474 ms | -65.999 ms | -3.2% |
|  | Median | 1868.060 ms | 1963.036 ms | +94.976 ms | +5.1% |
|  | Min | 1340.895 ms | 1277.200 ms | -63.695 ms | -4.8% |
|  | Max | 3388.789 ms | 2865.275 ms | -523.514 ms | -15.4% |
|  | Std Dev | 707.060 ms | 513.838 ms | -193.221 ms | -27.3% |
