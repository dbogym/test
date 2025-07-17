// package io.gaboja9.mockstock.global.Influx;
//
// import com.influxdb.client.InfluxDBClient;
// import com.influxdb.query.FluxRecord;
// import com.influxdb.query.FluxTable;
//
// import lombok.RequiredArgsConstructor;
//
// import org.springframework.stereotype.Service;
//
// import java.util.List;
//
// @Service
// @RequiredArgsConstructor
// public class InfluxQueryService {
//
//    private final InfluxDBClient influxDBClient;
//
//    public int getCurrentPrice(String stockCode) {
//        String flux =
//                String.format(
//                        """
//                            from(bucket: "stocks")
//                              |> range(start: -10m)
//                              |> filter(fn: (r) => r._measurement == "stock_price" and r.stockCode
// == "%s" and r._field == "price")
//                              |> last()
//                        """,
//                        stockCode);
//
//        List<FluxTable> tables = influxDBClient.getQueryApi().query(flux);
//
//        for (FluxTable table : tables) {
//            for (FluxRecord record : table.getRecords()) {
//                Object value = record.getValue();
//                if (value instanceof Number) {
//                    return ((Number) value).intValue();
//                }
//            }
//        }
//
//        throw new RuntimeException("시세 없음: " + stockCode);
//    }
// }
