#!/bin/bash

echo "Start Setup of Screen Sessions"

## utility
#create utility session and its windows
screen -dmS utility bash
screen -S utility -X screen -t "testbench"
screen -S utility -X screen -t "logging"
screen -S utility -X screen -t "wireshark"

# go to target folders
screen -S utility -p "testbench" -X stuff $'cd /root/Masterthesis/tls_servers/testbench/testbench\n'
screen -S utility -p "logging" -X stuff $'cd /root/Masterthesis/tls_servers/testbench/testbench/logging\n'
screen -S utility -p "wireshark" -X stuff $'cd /root/Masterthesis/tls_servers/testbench/testbench/logging\n'


## boringssl server
#create boringssl session and its windows
screen -dmS boringsslserver bash
screen -S boringsslserver -X screen -t "boring_ecc"
screen -S boringsslserver -X screen -t "boring_rsa"
screen -S boringsslserver -X screen -t "boring_ecc_ca"
screen -S boringsslserver -X screen -t "boring_ocsp_ecc256"
screen -S boringsslserver -X screen -t "boring_ocsp_ecc384"
screen -S boringsslserver -X screen -t "boring_ocsp_ecc521"
screen -S boringsslserver -X screen -t "boring_ocsp_rsa1024"
screen -S boringsslserver -X screen -t "boring_ocsp_rsa2048"
screen -S boringsslserver -X screen -t "boring_ocsp_rsa4096"

# go to target folder and start server
screen -S boringsslserver -p "boring_ecc" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3333 -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -loop > log_boring_ecc\n'
screen -S boringsslserver -p "boring_rsa" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3355 -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -loop > log_boring_rsa\n'
screen -S boringsslserver -p "boring_ecc_ca" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3443 -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -require-any-client-cert -loop > log_boring_ecc_ca\n'
screen -S boringsslserver -p "boring_ocsp_ecc256" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3364 -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -ocsp-response ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp256r1_ecdsa_cert.der -loop > log_boring_ocsp_ecc256\n'
screen -S boringsslserver -p "boring_ocsp_ecc384" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3366 -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -ocsp-response ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp384r1_ecdsa_cert.der -loop > log_boring_ocsp_ecc384\n'
screen -S boringsslserver -p "boring_ocsp_ecc521" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3367 -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -ocsp-response ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp521r1_ecdsa_cert.der -loop > log_boring_ocsp_ecc521\n'
screen -S boringsslserver -p "boring_ocsp_rsa1024" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3655 -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -ocsp-response ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa1024_ecdsa_cert.der -loop > log_boring_ocsp_rsa1024\n'
screen -S boringsslserver -p "boring_ocsp_rsa2048" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3656 -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -ocsp-response ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa2048_ecdsa_cert.der -loop > log_boring_ocsp_rsa2048\n'
screen -S boringsslserver -p "boring_ocsp_rsa4096" -X stuff $'cd /root/Masterthesis/tls_servers/boringssl/2024-08-12_boringssl\nexport SSLKEYLOGFILE=SSLKEYLOGFILE\ncd build\n./bssl s_server -accept 3657 -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -ocsp-response ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa4096_ecdsa_cert.der -loop > log_boring_ocsp_rsa4096\n'


## rustls server
#create rustls session and its windows
screen -dmS rustlsserver bash
screen -S rustlsserver -X screen -t "rustls_ecc"
screen -S rustlsserver -X screen -t "rustls_fast_ecc"
screen -S rustlsserver -X screen -t "rustls_rsa"
screen -S rustlsserver -X screen -t "rustls_fast_rsa"

screen -S rustlsserver -X screen -t "rustls_ecc_ca-ecdsa"
screen -S rustlsserver -X screen -t "rustls_ecc_ca-rsa"
screen -S rustlsserver -X screen -t "rustls_ecc_wr-ca-ec"
screen -S rustlsserver -X screen -t "rustls_ecc_wrong-ca-rsa"

screen -S rustlsserver -X screen -t "rustls_ecc_ticket"
screen -S rustlsserver -X screen -t "rustls_rsa_ticket"
screen -S rustlsserver -X screen -t "rustls_ecc_id"
screen -S rustlsserver -X screen -t "rustls_rsa_id"
screen -S rustlsserver -X screen -t "rustls_ocsp_ecc256"
screen -S rustlsserver -X screen -t "rustls_ocsp_ecc384"
screen -S rustlsserver -X screen -t "rustls_ocsp_ecc521"
screen -S rustlsserver -X screen -t "rustls_ocsp_rsa2048"
screen -S rustlsserver -X screen -t "rustls_ocsp_rsa4096"

# go to target folder and start server
screen -S rustlsserver -p "rustls_ecc" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --port 2222 echo > log_rustls_ecc\n'
screen -S rustlsserver -p "rustls_fast_ecc" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --release --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --port 45677 echo > log_rustls_fast_ecc\n'
screen -S rustlsserver -p "rustls_rsa" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem --port 2255 echo > log_rustls_rsa\n'
screen -S rustlsserver -p "rustls_fast_rsa" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --release --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem --port 48996 echo > log_rustls_fast_rsa\n'
screen -S rustlsserver -p "rustls_ecc_ca-ecdsa" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --auth ../TLS-Attacker/Zusatzzeug/certGen/attacker_ecdsa_ca.pem --require-auth --port 2332 echo > log_rustls_ecc_ca-ecdsa\n'
screen -S rustlsserver -p "rustls_ecc_ca-rsa" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --auth ../TLS-Attacker/Zusatzzeug/certGen/attacker_rsa_ca.pem --require-auth --port 2334 echo > log_rustls_ecc_ca-rsa\n'
screen -S rustlsserver -p "rustls_ecc_wr-ca-ec" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --auth ../TLS-Attacker/Zusatzzeug/certGen2/attacker_ecdsa_ca.pem --require-auth --port 2336 echo > log_rustls_ecc_wr-ca-ec\n'
screen -S rustlsserver -p "rustls_ecc_wrong-ca-rsa" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --auth ../TLS-Attacker/Zusatzzeug/certGen2/attacker_rsa_ca.pem --require-auth --port 2338 echo > log_rustls_ecc_wrong-ca-rsa\n'
screen -S rustlsserver -p "rustls_ecc_ticket" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --port 2221 --tickets echo > log_rustls_ecc_ticket\n'
screen -S rustlsserver -p "rustls_rsa_ticket" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem --port 2224 --tickets echo > log_rustls_rsa_ticket\n'
screen -S rustlsserver -p "rustls_ecc_id" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --port 2227 --resumption echo > log_rustls_ecc_id\n'
screen -S rustlsserver -p "rustls_rsa_id" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem --port 2229 echo > log_rustls_rsa_id\n'
screen -S rustlsserver -p "rustls_ocsp_ecc256" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem --ocsp ../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp256r1_ecdsa_cert.der --port 2355 echo > log_rustls_ocsp_ecc256\n'
screen -S rustlsserver -p "rustls_ocsp_ecc384" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem --ocsp ../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp384r1_ecdsa_cert.der --port 2356 echo > log_rustls_ocsp_ecc384\n'
screen -S rustlsserver -p "rustls_ocsp_ecc521" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem --ocsp ../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp521r1_ecdsa_cert.der --port 2357 echo > log_rustls_ocsp_ecc521\n'
screen -S rustlsserver -p "rustls_ocsp_rsa2048" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem --ocsp ../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa2048_ecdsa_cert.der  --port 2655 echo > log_rustls_ocsp_rsa2048\n'
screen -S rustlsserver -p "rustls_ocsp_rsa4096" -X stuff $'cd /root/Masterthesis/tls_servers/rustls\ncargo run --bin tlsserver-mio -- --certs ../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem --key ../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem --ocsp ../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa4096_ecdsa_cert.der  --port 2656 echo > log_rustls_ocsp_rsa4096\n'

## openssl server
#create openssl session and its windows
screen -dmS opensslserver bash
screen -S opensslserver -X screen -t "openssl111_ecc"
screen -S opensslserver -X screen -t "openssl111_ecc_renegote"
screen -S opensslserver -X screen -t "openssl111_rsa"
screen -S opensslserver -X screen -t "openssl111_ecc_ca-ecdsa"
screen -S opensslserver -X screen -t "openssl111_ecc_ca-rsa"
screen -S opensslserver -X screen -t "openssl111_ecc_wr-ca-ec"
screen -S opensslserver -X screen -t "openssl111_ecc_wrong-ca-rsa"
screen -S opensslserver -X screen -t "openssl111_ecc_id"
screen -S opensslserver -X screen -t "openssl111_rsa_id"
screen -S opensslserver -X screen -t "openssl111_256"
screen -S opensslserver -X screen -t "openssl111_384"
screen -S opensslserver -X screen -t "openssl111_521"
screen -S opensslserver -X screen -t "openssl111_2048"
screen -S opensslserver -X screen -t "openssl111_4096"

screen -S opensslserver -X screen -t "openssl333_ecc"
screen -S opensslserver -X screen -t "openssl333_rsa"

screen -S opensslserver -X screen -t "openssl333_ecc_ca-ecdsa"
screen -S opensslserver -X screen -t "openssl333_ecc_ca-rsa"
screen -S opensslserver -X screen -t "openssl333_ecc_wr-ca-ec"
screen -S opensslserver -X screen -t "openssl333_ecc_wrong-ca-rsa"

screen -S opensslserver -X screen -t "openssl333_ecc_id"
screen -S opensslserver -X screen -t "openssl333_rsa_id"
screen -S opensslserver -X screen -t "openssl333_256"
screen -S opensslserver -X screen -t "openssl333_384"
screen -S opensslserver -X screen -t "openssl333_521"
screen -S opensslserver -X screen -t "openssl333_2048"
screen -S opensslserver -X screen -t "openssl333_4096"

# go to target folder and start server
screen -S opensslserver -p "openssl111_ecc" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 1111 -early_data -no_anti_replay -num_tickets 1 > log_openssl111_ecc\n'
screen -S opensslserver -p "openssl111_ecc_renegote" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 3232 -early_data -no_anti_replay -num_tickets 1 > log_openssl111_ecc_renegote\n'
screen -S opensslserver -p "openssl111_rsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -port 1155 -early_data -no_anti_replay -num_tickets 1 > log_openssl111_rsa\n'
screen -S opensslserver -p "openssl111_ecc_ca-ecdsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 1115 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../TLS-Attacker/Zusatzzeug/certGen/attacker_ecdsa_ca.pem -verify_return_error > log_openssl111_ecc_ca-ecdsa\n'
screen -S opensslserver -p "openssl111_ecc_ca-rsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 1123 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../TLS-Attacker/Zusatzzeug/certGen/attacker_rsa_ca.pem -verify_return_error > log_openssl111_ecc_ca-rsa\n'
screen -S opensslserver -p "openssl111_ecc_wr-ca-ec" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 1124 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../TLS-Attacker/Zusatzzeug/certGen2/attacker_ecdsa_ca.pem -verify_return_error > log_openssl111_ecc_wr-ca-ec\n'
screen -S opensslserver -p "openssl111_ecc_wrong-ca-rsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 1126 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../TLS-Attacker/Zusatzzeug/certGen2/attacker_rsa_ca.pem -verify_return_error > log_openssl111_ecc_wrong-ca-rsa\n'
screen -S opensslserver -p "openssl111_ecc_id" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -stateless -port 11112 > log_openssl111_ecc_id\n'
screen -S opensslserver -p "openssl111_rsa_id" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -stateless -port 11116 > log_openssl111_rsa_id\n'
screen -S opensslserver -p "openssl111_ecc256" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -port 1433 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp256r1_ecdsa_cert.der > log_openssl111_ecc256\n'
screen -S opensslserver -p "openssl111_256" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -port 1433 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp256r1_ecdsa_cert.der > log_openssl111_256\n'
screen -S opensslserver -p "openssl111_384" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 1444 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp384r1_ecdsa_cert.der > log_openssl111_384\n'
screen -S opensslserver -p "openssl111_521" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -port 1445 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp521r1_ecdsa_cert.der > log_openssl111_521\n'
screen -S opensslserver -p "openssl111_2048" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -port 1555 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa2048_ecdsa_cert.der > log_openssl111_2048\n'
screen -S opensslserver -p "openssl111_4096" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_1-1-1w\ncd apps\n./openssl s_server -cert ../../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -key ../../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -port 1556 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa4096_ecdsa_cert.der > log_openssl111_4096\n'

screen -S opensslserver -p "openssl333_ecc" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 6666 -early_data -no_anti_replay -num_tickets 1 > log_openssl333_ecc\n'
screen -S opensslserver -p "openssl333_rsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -port 6655 -early_data -no_anti_replay -num_tickets 1 > log_openssl333_rsa\n'
screen -S opensslserver -p "openssl333_ecc_ca-ecdsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 6677 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../../TLS-Attacker/Zusatzzeug/certGen/attacker_ecdsa_ca.pem -verify_return_error > log_openssl333_ecc_ca-ecdsa\n'
screen -S opensslserver -p "openssl333_ecc_ca-rsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 6678 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../../TLS-Attacker/Zusatzzeug/certGen/attacker_rsa_ca.pem -verify_return_error > log_openssl333_ecc_ca-rsa\n'
screen -S opensslserver -p "openssl333_ecc_wr-ca-ec" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 6688 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../../TLS-Attacker/Zusatzzeug/certGen2/attacker_ecdsa_ca.pem -verify_return_error > log_openssl333_ecc_wr-ca-ec\n'
screen -S opensslserver -p "openssl333_ecc_wrong-ca-rsa" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 6689 -early_data -no_anti_replay -num_tickets 1 -Verify 3 -CAfile ../../../../TLS-Attacker/Zusatzzeug/certGen2/attacker_rsa_ca.pem -verify_return_error > log_openssl333_ecc_wrong-ca-rsa\n'
screen -S opensslserver -p "openssl333_ecc_id" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -stateless -port 6662 > log_openssl333_ecc_id > log_openssl333_ecc_id\n'
screen -S opensslserver -p "openssl333_rsa_id" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -stateless -port 6552 > log_openssl333_rsa_id > log_openssl333_rsa_id\n'
screen -S opensslserver -p "openssl333_256" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -port 6433 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp256r1_ecdsa_cert.der > log_openssl333_256\n'
screen -S opensslserver -p "openssl333_384" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -port 6444 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp384r1_ecdsa_cert.der > log_openssl333_384\n'
screen -S opensslserver -p "openssl333_521" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -port 6445 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_ec_secp521r1_ecdsa_cert.der > log_openssl333_521\n'
screen -S opensslserver -p "openssl333_2048" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -port 6555 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa2048_ecdsa_cert.der > log_openssl333_2048\n'
screen -S opensslserver -p "openssl333_4096" -X stuff $'cd /root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\nexport LD_LIBRARY_PATH=/root/Masterthesis/tls_servers/openssl/openssl_3-3-1/openssl-3.3.1\ncd apps\n./openssl s_server -cert ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -key ../../../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -port 6556 -early_data -no_anti_replay -num_tickets 1 -status_file ../../../../TLS-Attacker/Zusatzzeug/certGen/OCSP/ocsp_resp_rsa4096_ecdsa_cert.der > log_openssl333_4096\n'


## wolfssl server
#create wolfssl session and its windows
screen -dmS wolfsslserver bash
screen -S wolfsslserver -X screen -t "wolf_ecc_tls12"
screen -S wolfsslserver -X screen -t "wolf_slow_ecc_tls12"
screen -S wolfsslserver -X screen -t "wolf_rsa_tls12"
screen -S wolfsslserver -X screen -t "wolf_slow_rsa_tls12"
screen -S wolfsslserver -X screen -t "wolf_ecc256_tls12"
screen -S wolfsslserver -X screen -t "wolf_ecc521_tls12"
screen -S wolfsslserver -X screen -t "wolf_rsa1024_tls12"
screen -S wolfsslserver -X screen -t "wolf_rsa4096_tls12"
screen -S wolfsslserver -X screen -t "wolf_ecc_tls13"
screen -S wolfsslserver -X screen -t "wolf_rsa_tls13"
screen -S wolfsslserver -X screen -t "wolf_slow_rsa_tls13"
screen -S wolfsslserver -X screen -t "wolf_ecc_tls13_0rtt"
screen -S wolfsslserver -X screen -t "wolf_rsa_tls13_0rtt"
screen -S wolfsslserver -X screen -t "wolf_ecc256_tls13"
screen -S wolfsslserver -X screen -t "wolf_ecc521_tls13"
screen -S wolfsslserver -X screen -t "wolf_rsa1024_tls13"
screen -S wolfsslserver -X screen -t "wolf_rsa4096_tls13"

screen -S wolfsslserver -X screen -t "wolf_ecc_ca_ec_12"
screen -S wolfsslserver -X screen -t "wolf_ecc_ca_rsa_12"
screen -S wolfsslserver -X screen -t "wolf_wr-ca_ec_12"
screen -S wolfsslserver -X screen -t "wolf_wr-ca_rsa_12"
screen -S wolfsslserver -X screen -t "wolf_ecc_ca_ec_13"
screen -S wolfsslserver -X screen -t "wolf_ecc_ca_rsa_13"
screen -S wolfsslserver -X screen -t "wolf_wr-ca_ec_13"
screen -S wolfsslserver -X screen -t "wolf_wr-ca_rsa_13"



# go to target folder and start server
#screen -S wolfsslserver -p "wolf_ecc_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 4444 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_rsa_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 4455 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_ecc256_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44556 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_ecc521_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44566 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_rsa1024_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44567 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_rsa4096_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44568 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_ecc_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44443 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_rsa_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44553 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_ecc_tls13_0rtt" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44422 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f -0\n'
#screen -S wolfsslserver -p "wolf_rsa_tls13_0rtt" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44522 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f -0\n'
#screen -S wolfsslserver -p "wolf_ecc256_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44551 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_ecc521_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44562 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_rsa1024_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 4453 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -d -i -f\n'
#screen -S wolfsslserver -p "wolf_rsa4096_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 44563 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -d -i -f\n'

# setup for WolfSSL ECDHE-DHE Test
#screen -S wolfsslserver -p "wolf_rsa_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math\nsudo ./examples/server/server -p 4455 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f\n'

# wolfSSL with enable-fast and FFDHE3072
#screen -S wolfsslserver -p "wolf_ecc_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 4444 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f > log_wolf_ecc_tls12\n'
#screen -S wolfsslserver -p "wolf_rsa_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 4455 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f > log_wolf_rsa_tls12\n'
#screen -S wolfsslserver -p "wolf_ecc256_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44556 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -d -i -f > log_wolf_ecc256_tls12\n'
#screen -S wolfsslserver -p "wolf_ecc521_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44566 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -d -i -f > log_wolf_ecc521_tls12\n'
#screen -S wolfsslserver -p "wolf_rsa1024_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44567 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -d -i -f > log_wolf_rsa1024_tls12\n'
#screen -S wolfsslserver -p "wolf_rsa4096_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44568 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -d -i -f > log_wolf_rsa4096_tls12\n'
#screen -S wolfsslserver -p "wolf_ecc_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44443 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f > log_wolf_ecc_tls13\n'
#screen -S wolfsslserver -p "wolf_rsa_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44553 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f > log_wolf_rsa_tls13\n'
#screen -S wolfsslserver -p "wolf_ecc_tls13_0rtt" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44422 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f -0 > log_wolf_ecc_tls13_0rtt\n'
#screen -S wolfsslserver -p "wolf_rsa_tls13_0rtt" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44522 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f -0 > log_wolf_rsa_tls13_0rtt\n'
#screen -S wolfsslserver -p "wolf_ecc256_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44551 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -d -i -f > log_wolf_ecc256_tls13\n'
#screen -S wolfsslserver -p "wolf_ecc521_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44562 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -d -i -f > log_wolf_ecc521_tls13\n'
#screen -S wolfsslserver -p "wolf_rsa1024_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 4453 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -d -i -f > log_wolf_rsa1024_tls13\n'
#screen -S wolfsslserver -p "wolf_rsa4096_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072\nsudo ./examples/server/server -p 44563 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -d -i -f > log_wolf_rsa4096_tls13\n'

# wolfSSL with enable-fast and FFDHE3072 and early data
screen -S wolfsslserver -p "wolf_ecc_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4444 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f > log_wolf_ecc_tls12\n'
screen -S wolfsslserver -p "wolf_slow_ecc_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 4564 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f > log_wolf_slow_ecc_tls12\n'
screen -S wolfsslserver -p "wolf_rsa_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4455 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f > log_wolf_rsa_tls12\n'
screen -S wolfsslserver -p "wolf_slow_rsa_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 48556 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f > log_wolf_slow_rsa_tls12\n'
screen -S wolfsslserver -p "wolf_ecc256_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44556 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -d -i -f > log_wolf_ecc256_tls12\n'
screen -S wolfsslserver -p "wolf_ecc521_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44566 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -d -i -f > log_wolf_ecc521_tls12\n'
screen -S wolfsslserver -p "wolf_rsa1024_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44567 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -d -i -f > log_wolf_rsa1024_tls12\n'
screen -S wolfsslserver -p "wolf_rsa4096_tls12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44568 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -d -i -f > log_wolf_rsa4096_tls12\n'
screen -S wolfsslserver -p "wolf_ecc_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44443 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f > log_wolf_ecc_tls13\n'
screen -S wolfsslserver -p "wolf_rsa_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44553 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f > log_wolf_rsa_tls13\n'
screen -S wolfsslserver -p "wolf_slow_rsa_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-all\nsudo ./examples/server/server -p 48553 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f > log_wolf_slow_rsa_tls13\n'
screen -S wolfsslserver -p "wolf_ecc_tls13_0rtt" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44422 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -d -i -f -0 > log_wolf_ecc_tls13_0rtt\n'
screen -S wolfsslserver -p "wolf_rsa_tls13_0rtt" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44522 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa2048_key.pem -d -i -f -0 > log_wolf_rsa_tls13_0rtt\n'
screen -S wolfsslserver -p "wolf_ecc256_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44551 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_key.pem -d -i -f > log_wolf_ecc256_tls13\n'
screen -S wolfsslserver -p "wolf_ecc521_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44562 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_key.pem -d -i -f > log_wolf_ecc521_tls13\n'
screen -S wolfsslserver -p "wolf_rsa1024_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4453 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa1024_key.pem -d -i -f > log_wolf_rsa1024_tls13\n'
screen -S wolfsslserver -p "wolf_rsa4096_tls13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44563 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/rsa4096_key.pem -d -i -f > log_wolf_rsa4096_tls13\n'

screen -S wolfsslserver -p "wolf_ecc_ca_ec_12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4456 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen/attacker_ecdsa_ca.pem > log_wolf_ecc_ca_ecdsa_tls12\n'
screen -S wolfsslserver -p "wolf_ecc_ca_rsa_12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4457 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen/attacker_rsa_ca.pem > log_wolf_ecc_ca_rsa_tls12\n'
screen -S wolfsslserver -p "wolf_wr-ca_ec_12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4458 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen2/attacker_ecdsa_ca.pem > log_wolf_ecc_wr-ca_ecdsa_tls12\n'
screen -S wolfsslserver -p "wolf_wr-ca_rsa_12" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 4459 -v 3 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen2/attacker_rsa_ca.pem > log_wolf_ecc_wr-ca_rsa_tls12\n'
screen -S wolfsslserver -p "wolf_ecc_ca_ec_13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44510 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen/attacker_ecdsa_ca.pem > log_wolf_ecc_ca_ecdsa_tls13\n'
screen -S wolfsslserver -p "wolf_ecc_ca_rsa_13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44511 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen/attacker_rsa_ca.pem > log_wolf_ecc_ca_rsa_tls13\n'
screen -S wolfsslserver -p "wolf_wr-ca_ec_13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44512 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen2/attacker_ecdsa_ca.pem > log_wolf_ecc_wr-ca_ecdsa_tls13\n'
screen -S wolfsslserver -p "wolf_wr-ca_rsa_13" -X stuff $'cd /root/Masterthesis/tls_servers/wolfssl/wolfssl-5.7.2_enable-fast-math-3072-0rtt\nsudo ./examples/server/server -p 44513 -v 4 -c ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem -k ../../TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_key.pem -i -f -x -A ../../TLS-Attacker/Zusatzzeug/certGen2/attacker_rsa_ca.pem > log_wolf_ecc_wr-ca_rsa_tls13\n'


echo "Finished Setup of Screen Sessions"
