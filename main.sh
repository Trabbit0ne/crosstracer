#!/bin/bash

# Clear the screen
clear

# XST Vulnerability Checker - 100% Accurate Validation

# Output file for vulnerable targets
OUTPUT_FILE="vulnerable.txt"
> "$OUTPUT_FILE"  # Clear the file if it exists

# Function to check a single target for XST vulnerability
check_xst() {
    local TARGET="$1"
    local MAX_REDIRECTS=10
    local REDIRECT_COUNT=0

    echo "Starting XST vulnerability check for $TARGET"

    while :; do
        # Send TRACE request and capture full response headers and body
        RESPONSE=$(curl -s -X TRACE -D - "$TARGET" -H "X-Test-Header: VulnerableCheck" --max-time 2)
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
                echo "$TARGET" >> "$OUTPUT_FILE"  # Write the vulnerable target to the output file
            else
                echo "[i] TRACE method is enabled, but headers are NOT reflected. The server is not vulnerable to XST."
            fi
            return
        fi

        # Handle redirection (Location header)
        LOCATION=$(echo "$RESPONSE" | grep -i '^Location:' | awk '{print $2}' | tr -d '\r')
        if [ -z "$LOCATION" ]; then
            echo "No redirection found. Final response status code: $STATUS_CODE."
            echo "TRACE method is not enabled or server does not reflect headers."
            return
        fi

        # Prevent infinite redirection loops
        if [ "$REDIRECT_COUNT" -ge "$MAX_REDIRECTS" ]; then
            echo "Maximum redirection limit reached. Exiting."
            return
        fi

        echo "Following redirect to $LOCATION"
        TARGET=$LOCATION
        REDIRECT_COUNT=$((REDIRECT_COUNT + 1))
    done
}

# Check if at least one argument is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <target-domain> OR $0 -m <file-with-domains>"
    exit 1
fi

# Check if the user provided the -m option for a file
if [ "$1" == "-m" ]; then
    if [ -z "$2" ]; then
        echo "Error: No file provided with the -m option."
        exit 1
    fi

    if [ ! -f "$2" ]; then
        echo "Error: File '$2' not found."
        exit 1
    fi

    # Read the file line by line and check each URL/domain
    while IFS= read -r line; do
        # Skip empty lines or lines starting with a comment (#)
        if [ -z "$line" ] || [[ "$line" == \#* ]]; then
            continue
        fi

        check_xst "$line"
        echo "========================================="
    done < "$2"

else
    # Single target provided
    check_xst "$1"
fi

echo "Vulnerability check completed. Vulnerable targets (if any) are saved in $OUTPUT_FILE."
