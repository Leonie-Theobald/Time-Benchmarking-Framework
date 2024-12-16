## Start Time Benchmarking Framework
### Preparation server
- start TLS server on socket that was used in preparation testbench
- server must be configured in a way to be able to perform the desired test scenario (e.g. if the testcase is about TLS1.3, the server must support this)

for reference configurations ofr some libraries see Misc/screen-setup-server.sh (screen-clearing.sh can be used to erase screen session)

### Preparation testbench
- test config: add test case(s) of interest (selection available in comments* but own definition also possible)
- outbound connection: add details to what server testbench should connect (ip, port, etc.)
- handshake flow: specify what flow the client should follow
- call start test: specify details such as test case name, repetition, link to config and handshake flow, whether the results should be logged in a file, statistic parameters

*file references of certitifactes and keys need to be adapted to match local setup / cryptographic content is available in Misc

- start with: ```mvn clean install -DskipTests=true; java -cp target/testbench-1.0-SNAPSHOT-jar-with-dependencies.jar app.App```