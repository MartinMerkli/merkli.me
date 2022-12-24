#!/usr/bin/env bash

while sleep 21600; do
    source /home/ubuntu/server/venv/bin/activate;
    python3 /home/ubuntu/server/get_mensa.py;
    deactivate;
done
