return function(ctx)
    local TX = ctx.TX
    if TX.BLOCKING_PARANOIA_LEVEL >= 1 then
        TX.BLOCKING_INBOUND_ANOMALY_SCORE = TX.BLOCKING_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL1
    end
    if TX.BLOCKING_PARANOIA_LEVEL >= 2 then
        TX.BLOCKING_INBOUND_ANOMALY_SCORE = TX.BLOCKING_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL2
    end
    if TX.BLOCKING_PARANOIA_LEVEL >= 3 then
        TX.BLOCKING_INBOUND_ANOMALY_SCORE = TX.BLOCKING_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL3
    end
    if TX.BLOCKING_PARANOIA_LEVEL >= 4 then
        TX.BLOCKING_INBOUND_ANOMALY_SCORE = TX.BLOCKING_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL4
    end
    if TX.DETECTION_PARANOIA_LEVEL >= 1 then
        TX.DETECTION_INBOUND_ANOMALY_SCORE = TX.DETECTION_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL1
    end
    if TX.DETECTION_PARANOIA_LEVEL >= 2 then
        TX.DETECTION_INBOUND_ANOMALY_SCORE = TX.DETECTION_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL2
    end
    if TX.DETECTION_PARANOIA_LEVEL >= 3 then
        TX.DETECTION_INBOUND_ANOMALY_SCORE = TX.DETECTION_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL3
    end
    if TX.DETECTION_PARANOIA_LEVEL >= 4 then
        TX.DETECTION_INBOUND_ANOMALY_SCORE = TX.DETECTION_INBOUND_ANOMALY_SCORE + TX.INBOUND_ANOMALY_SCORE_PL4
    end
    return TX.BLOCKING_INBOUND_ANOMALY_SCORE >= TX.INBOUND_ANOMALY_SCORE_THRESHOLD
end