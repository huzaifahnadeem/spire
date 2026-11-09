# MonPoly argument map

Timestamps are in **us** (scaled from the microsecond id key; divisor 1). Metric intervals in the policies are in the same unit.

## `hmi_proxy_main_msg`

| pos | variable | field path | type |
|----|----|----|----|
| 0 | `system_id` | `from.system_ID` | string |
| 1 | `len` | `data.message_content.len` | int |
| 2 | `breaker_read_0` | `data.message_content.payload.breaker_read[0]` | int |
| 3 | `breaker_read_10` | `data.message_content.payload.breaker_read[10]` | int |
| 4 | `breaker_read_11` | `data.message_content.payload.breaker_read[11]` | int |
| 5 | `breaker_read_12` | `data.message_content.payload.breaker_read[12]` | int |
| 6 | `breaker_read_13` | `data.message_content.payload.breaker_read[13]` | int |
| 7 | `breaker_read_1` | `data.message_content.payload.breaker_read[1]` | int |
| 8 | `breaker_read_2` | `data.message_content.payload.breaker_read[2]` | int |
| 9 | `breaker_read_3` | `data.message_content.payload.breaker_read[3]` | int |
| 10 | `breaker_read_4` | `data.message_content.payload.breaker_read[4]` | int |
| 11 | `breaker_read_5` | `data.message_content.payload.breaker_read[5]` | int |
| 12 | `breaker_read_6` | `data.message_content.payload.breaker_read[6]` | int |
| 13 | `breaker_read_7` | `data.message_content.payload.breaker_read[7]` | int |
| 14 | `breaker_read_8` | `data.message_content.payload.breaker_read[8]` | int |
| 15 | `breaker_read_9` | `data.message_content.payload.breaker_read[9]` | int |
| 16 | `breaker_write_0` | `data.message_content.payload.breaker_write[0]` | int |
| 17 | `breaker_write_10` | `data.message_content.payload.breaker_write[10]` | int |
| 18 | `breaker_write_11` | `data.message_content.payload.breaker_write[11]` | int |
| 19 | `breaker_write_12` | `data.message_content.payload.breaker_write[12]` | int |
| 20 | `breaker_write_13` | `data.message_content.payload.breaker_write[13]` | int |
| 21 | `breaker_write_1` | `data.message_content.payload.breaker_write[1]` | int |
| 22 | `breaker_write_2` | `data.message_content.payload.breaker_write[2]` | int |
| 23 | `breaker_write_3` | `data.message_content.payload.breaker_write[3]` | int |
| 24 | `breaker_write_4` | `data.message_content.payload.breaker_write[4]` | int |
| 25 | `breaker_write_5` | `data.message_content.payload.breaker_write[5]` | int |
| 26 | `breaker_write_6` | `data.message_content.payload.breaker_write[6]` | int |
| 27 | `breaker_write_7` | `data.message_content.payload.breaker_write[7]` | int |
| 28 | `breaker_write_8` | `data.message_content.payload.breaker_write[8]` | int |
| 29 | `breaker_write_9` | `data.message_content.payload.breaker_write[9]` | int |
| 30 | `point_0` | `data.message_content.payload.point[0]` | int |
| 31 | `point_1` | `data.message_content.payload.point[1]` | int |
| 32 | `point_2` | `data.message_content.payload.point[2]` | int |
| 33 | `point_3` | `data.message_content.payload.point[3]` | int |
| 34 | `point_4` | `data.message_content.payload.point[4]` | int |
| 35 | `point_5` | `data.message_content.payload.point[5]` | int |
| 36 | `point_6` | `data.message_content.payload.point[6]` | int |
| 37 | `point_7` | `data.message_content.payload.point[7]` | int |
| 38 | `scen_type` | `data.message_content.scen_type` | int |
| 39 | `sec` | `data.message_content.sec` | int |
| 40 | `incarnation` | `data.message_content.seq.incarnation` | int |
| 41 | `seq_num` | `data.message_content.seq.seq_num` | int |
| 42 | `usec` | `data.message_content.usec` | int |

## `hmi_proxy_shadow_msg`

| pos | variable | field path | type |
|----|----|----|----|
| 0 | `system_id` | `from.system_ID` | string |
| 1 | `len` | `data.message_content.len` | int |
| 2 | `breaker_read_0` | `data.message_content.payload.breaker_read[0]` | int |
| 3 | `breaker_read_10` | `data.message_content.payload.breaker_read[10]` | int |
| 4 | `breaker_read_11` | `data.message_content.payload.breaker_read[11]` | int |
| 5 | `breaker_read_12` | `data.message_content.payload.breaker_read[12]` | int |
| 6 | `breaker_read_13` | `data.message_content.payload.breaker_read[13]` | int |
| 7 | `breaker_read_1` | `data.message_content.payload.breaker_read[1]` | int |
| 8 | `breaker_read_2` | `data.message_content.payload.breaker_read[2]` | int |
| 9 | `breaker_read_3` | `data.message_content.payload.breaker_read[3]` | int |
| 10 | `breaker_read_4` | `data.message_content.payload.breaker_read[4]` | int |
| 11 | `breaker_read_5` | `data.message_content.payload.breaker_read[5]` | int |
| 12 | `breaker_read_6` | `data.message_content.payload.breaker_read[6]` | int |
| 13 | `breaker_read_7` | `data.message_content.payload.breaker_read[7]` | int |
| 14 | `breaker_read_8` | `data.message_content.payload.breaker_read[8]` | int |
| 15 | `breaker_read_9` | `data.message_content.payload.breaker_read[9]` | int |
| 16 | `breaker_write_0` | `data.message_content.payload.breaker_write[0]` | int |
| 17 | `breaker_write_10` | `data.message_content.payload.breaker_write[10]` | int |
| 18 | `breaker_write_11` | `data.message_content.payload.breaker_write[11]` | int |
| 19 | `breaker_write_12` | `data.message_content.payload.breaker_write[12]` | int |
| 20 | `breaker_write_13` | `data.message_content.payload.breaker_write[13]` | int |
| 21 | `breaker_write_1` | `data.message_content.payload.breaker_write[1]` | int |
| 22 | `breaker_write_2` | `data.message_content.payload.breaker_write[2]` | int |
| 23 | `breaker_write_3` | `data.message_content.payload.breaker_write[3]` | int |
| 24 | `breaker_write_4` | `data.message_content.payload.breaker_write[4]` | int |
| 25 | `breaker_write_5` | `data.message_content.payload.breaker_write[5]` | int |
| 26 | `breaker_write_6` | `data.message_content.payload.breaker_write[6]` | int |
| 27 | `breaker_write_7` | `data.message_content.payload.breaker_write[7]` | int |
| 28 | `breaker_write_8` | `data.message_content.payload.breaker_write[8]` | int |
| 29 | `breaker_write_9` | `data.message_content.payload.breaker_write[9]` | int |
| 30 | `point_0` | `data.message_content.payload.point[0]` | int |
| 31 | `point_1` | `data.message_content.payload.point[1]` | int |
| 32 | `point_2` | `data.message_content.payload.point[2]` | int |
| 33 | `point_3` | `data.message_content.payload.point[3]` | int |
| 34 | `point_4` | `data.message_content.payload.point[4]` | int |
| 35 | `point_5` | `data.message_content.payload.point[5]` | int |
| 36 | `point_6` | `data.message_content.payload.point[6]` | int |
| 37 | `point_7` | `data.message_content.payload.point[7]` | int |
| 38 | `scen_type` | `data.message_content.scen_type` | int |
| 39 | `sec` | `data.message_content.sec` | int |
| 40 | `incarnation` | `data.message_content.seq.incarnation` | int |
| 41 | `seq_num` | `data.message_content.seq.seq_num` | int |
| 42 | `usec` | `data.message_content.usec` | int |

## `rtu_proxy_main_msg`

| pos | variable | field path | type |
|----|----|----|----|
| 0 | `system_id` | `from.system_ID` | string |
| 1 | `offset` | `data.message_content.offset` | int |
| 2 | `rtu` | `data.message_content.rtu` | int |
| 3 | `scen_type` | `data.message_content.scen_type` | int |
| 4 | `incarnation` | `data.message_content.seq.incarnation` | int |
| 5 | `seq_num` | `data.message_content.seq.seq_num` | int |
| 6 | `sub` | `data.message_content.sub` | int |
| 7 | `type` | `data.message_content.type` | int |
| 8 | `val` | `data.message_content.val` | int |

## `rtu_proxy_shadow_msg`

| pos | variable | field path | type |
|----|----|----|----|
| 0 | `system_id` | `from.system_ID` | string |
| 1 | `offset` | `data.message_content.offset` | int |
| 2 | `rtu` | `data.message_content.rtu` | int |
| 3 | `scen_type` | `data.message_content.scen_type` | int |
| 4 | `incarnation` | `data.message_content.seq.incarnation` | int |
| 5 | `seq_num` | `data.message_content.seq.seq_num` | int |
| 6 | `sub` | `data.message_content.sub` | int |
| 7 | `type` | `data.message_content.type` | int |
| 8 | `val` | `data.message_content.val` | int |

