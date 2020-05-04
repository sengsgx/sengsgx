#!/bin/bash
sudo -E nice -n -20 bash -c "telnet -4 ${*}"
