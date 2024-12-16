#!/bin/bash

echo "Start Clearing of Screen Sessions"

screen -S utility -X quit
screen -S boringsslserver -X quit
screen -S rustlsserver -X quit
screen -S opensslserver -X quit
screen -S wolfsslserver -X quit

echo "Finished Clearing of Screen Sessions"
