#!/bin/sh

# Install boto3 into the existing cowrie environment if it is missing
# (Done here so we avoid needing to run as root during docker build layer caching)
if ! /cowrie/cowrie-env/bin/python3 -c "import boto3" 2>/dev/null; then
    echo "Installing boto3 for log shipper..."
    /cowrie/cowrie-env/bin/pip install boto3
fi

# Start the log tailer in the background
/cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/log_shipper.py &

# Start Cowrie (the original default CMD is twistd...)
echo "Starting Cowrie honeypot..."
exec "$@"
