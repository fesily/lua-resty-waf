return function(ctx) ctx.storage.TX = ctx.storage.TX or {};
    local TX = ctx.storage.TX;
    TX.CRS_SETUP_VERSION = TX.CRS_SETUP_VERSION or 340;
    TX.INBOUND_ANOMALY_SCORE_THRESHOLD = TX.INBOUND_ANOMALY_SCORE_THRESHOLD or 5;
    TX.OUTBOUND_ANOMALY_SCORE_THRESHOLD = TX.OUTBOUND_ANOMALY_SCORE_THRESHOLD or 4;
    TX.REPORTING_LEVEL = TX.REPORTING_LEVEL or 4;
    TX.EARLY_BLOCKING = TX.EARLY_BLOCKING or 0;
    TX.BLOCKING_PARANOIA_LEVEL = TX.BLOCKING_PARANOIA_LEVEL or 1;
    TX.DETECTION_PARANOIA_LEVEL = TX.DETECTION_PARANOIA_LEVEL or TX.BLOCKING_PARANOIA_LEVEL;
    TX.SAMPLING_PERCENTAGE = TX.SAMPLING_PERCENTAGE or 100;
    TX.CRITICAL_ANOMALY_SCORE = TX.CRITICAL_ANOMALY_SCORE or 5;
    TX.ERROR_ANOMALY_SCORE = TX.ERROR_ANOMALY_SCORE or 4;
    TX.WARNING_ANOMALY_SCORE = TX.WARNING_ANOMALY_SCORE or 3;
    TX.NOTICE_ANOMALY_SCORE = TX.NOTICE_ANOMALY_SCORE or 2;
    TX.DO_REPUT_BLOCK = TX.DO_REPUT_BLOCK or 0;
    TX.REPUT_BLOCK_DURATION = TX.REPUT_BLOCK_DURATION or 300;
    TX.ALLOWED_METHODS = TX.ALLOWED_METHODS or [[GET HEAD POST OPTIONS]];
    TX.ALLOWED_REQUEST_CONTENT_TYPE = TX.ALLOWED_REQUEST_CONTENT_TYPE or [[|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/x-amf| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/octet-stream| |application/csp-report| |application/xss-auditor-report| |text/plain|]];
    TX.ALLOWED_REQUEST_CONTENT_TYPE_CHARSET = TX.ALLOWED_REQUEST_CONTENT_TYPE_CHARSET or [[|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|]];
    TX.ALLOWED_HTTP_VERSIONS = TX.ALLOWED_HTTP_VERSIONS or [[HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0]];
    TX.RESTRICTED_EXTENSIONS = TX.RESTRICTED_EXTENSIONS or [[.asa/ .asax/ .ascx/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/]];
    TX.RESTRICTED_HEADERS = TX.RESTRICTED_HEADERS or [[/proxy/ /lock-token/ /content-range/ /if/ /user-agentt/]];
    TX.ENFORCE_BODYPROC_URLENCODED = TX.ENFORCE_BODYPROC_URLENCODED or 0;
    TX.BLOCKING_INBOUND_ANOMALY_SCORE = 0;
    TX.DETECTION_INBOUND_ANOMALY_SCORE = 0;
    TX.INBOUND_ANOMALY_SCORE_PL1 = 0;
    TX.INBOUND_ANOMALY_SCORE_PL2 = 0;
    TX.INBOUND_ANOMALY_SCORE_PL3 = 0;
    TX.INBOUND_ANOMALY_SCORE_PL4 = 0;
    TX.SQL_INJECTION_SCORE = 0;
    TX.XSS_SCORE = 0;
    TX.RFI_SCORE = 0;
    TX.LFI_SCORE = 0;
    TX.RCE_SCORE = 0;
    TX.PHP_INJECTION_SCORE = 0;
    TX.HTTP_VIOLATION_SCORE = 0;
    TX.SESSION_FIXATION_SCORE = 0;
    TX.BLOCKING_OUTBOUND_ANOMALY_SCORE = 0;
    TX.DETECTION_OUTBOUND_ANOMALY_SCORE = 0;
    TX.OUTBOUND_ANOMALY_SCORE_PL1 = 0;
    TX.OUTBOUND_ANOMALY_SCORE_PL2 = 0;
    TX.OUTBOUND_ANOMALY_SCORE_PL3 = 0;
    TX.OUTBOUND_ANOMALY_SCORE_PL4 = 0;
    TX.SQL_ERROR_MATCH = 0;
end
