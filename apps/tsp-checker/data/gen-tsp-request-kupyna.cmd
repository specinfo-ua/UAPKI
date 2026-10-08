echo "Generate (and send) TSP-requests with KUPYNA-family"

set TSP_UTIL=tsp-checker
set URL_TSP=http://ca-test.czo.gov.ua/services/tsp/
set DIGEST_256=11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF
set DIGEST_384=11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF
set DIGEST_512=11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF
set NONCE_HEX=00BC614E

echo "Generate (and send) TSP-requests with KUPYNA-256"
set DIGEST_ALGO=1.2.804.2.1.1.1.1.2.2.1
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_256% --save-request request-kupyna256.tsq
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_256% --nonce-hex %NONCE_HEX% --cert-req --save-request request-kupyna256-nonce-certReq.tsq

echo "Generate (and send) TSP-requests with KUPYNA-384"
set DIGEST_ALGO=1.2.804.2.1.1.1.1.2.2.2
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_384% --save-request request-kupyna384.tsq
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_384% --nonce-hex %NONCE_HEX% --cert-req --save-request request-kupyna384-nonce-certReq.tsq

echo "Generate (and send) TSP-requests with KUPYNA-384"
set DIGEST_ALGO=1.2.804.2.1.1.1.1.2.2.3
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_512% --save-request request-kupyna512.tsq
%TSP_UTIL% --url %URL_TSP% --digest-algo %DIGEST_ALGO% --digest %DIGEST_512% --nonce-hex %NONCE_HEX% --cert-req --save-request request-kupyna512-nonce-certReq.tsq

pause
