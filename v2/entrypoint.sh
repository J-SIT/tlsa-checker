#!/bin/bash

# Prüfen, ob ein Testmodus aktiv ist
if [ "$MODE" = "test" ]; then
    python /app/check_tlsa.py
else
    while true; do
        echo "Starting TLSA check..."
        python /app/check_tlsa.py
        echo "Check completed. Waiting for next interval ($CHECK_INTERVAL seconds)..."
        sleep $CHECK_INTERVAL
    done
fi
