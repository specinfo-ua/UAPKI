echo "Generate (and send) TSP-requests with GOST-34311"

set TSP_UTIL=tsp-checker
set URL_TSP=http://ca-test.czo.gov.ua/services/tsp/
set DIGEST_256=11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF
set DIGEST_ALGO=gost-34311
set REQ_POLICY=1.2.804.2.1.1.1.2.3.1
set NONCE_HEX=00BC614E

%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_256% --save-request request-gost34311.tsq
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_256% --req-policy %REQ_POLICY% --nonce-hex %NONCE_HEX% --cert-req --save-request request-gost34311-reqPolicy-nonce-certReq.tsq

pause
