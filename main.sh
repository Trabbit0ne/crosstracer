#!/bin/bash

# clear the sreen
clear

# XST Vulnerability Checker - 100% Accurate Validation

# Check if a domain is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi

TARGET=$1
MAX_REDIRECTS=10
REDIRECT_COUNT=0

echo "Starting XST vulnerability check for $TARGET"

while :; do
    # Send TRACE request and capture full response headers and body
    RESPONSE=$(curl -s -X TRACE -D - "$TARGET" -H "X-Test-Header: VulnerableCheck")
    STATUS_CODE=$(echo "$RESPONSE" | grep -oP "HTTP/1.\d \K\d{3}")

    # Check for a 200 OK response
    if [ "$STATUS_CODE" == "200" ]; then
        echo "-----------------------------------------"
        echo "Final Response from $TARGET:"
        echo "$RESPONSE"
        echo "-----------------------------------------"

        # Check if TRACE is allowed and headers are reflected
        if echo "$RESPONSE" | grep -qi "X-Test-Header: VulnerableCheck"; then
            echo "[i] TRACE method is enabled, and headers are reflected. The server is 100% vulnerable to XST."
        else
            echo "[i] TRACE method is enabled, but headers are NOT reflected. The server is not vulnerable to XST."
        fi
        exit 0
    fi

    # Handle redirection (Location header)
    LOCATION=$(echo "$RESPONSE" | grep -i '^Location:' | awk '{print $2}' | tr -d '\r')
    if [ -z "$LOCATION" ]; then
        echo "No redirection found. Final response status code: $STATUS_CODE."
        echo "TRACE method is not enabled or server does not reflect headers."
        exit 0
    fi

    # Prevent infinite redirection loops
    if [ "$REDIRECT_COUNT" -ge "$MAX_REDIRECTS" ]; then
        echo "Maximum redirection limit reached. Exiting."
        exit 1
    fi

    echo "Following redirect to $LOCATION"
    TARGET=$LOCATION
    REDIRECT_COUNT=$((REDIRECT_COUNT + 1))
done
