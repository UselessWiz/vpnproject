#!/bin/bash

# Start the containers
docker compose build
docker compose up -d

# Benhcmark each version individually
versions=("RSA" "QUIC" "X25519")

# To run benchmarking (bash terminals or similar)
for version in "${versions[@]}";
do
    echo "Benchmark running - ${version}"
    docker exec -itd server-router env PYTHONPATH=/volumes python3 /volumes/server/${version}_server.py
    sleep 2
    docker exec -itd client-10.9.0.5 env PYTHONPATH=/volumes python3 /volumes/client/${version}_client.py
    sleep 2
    env python3 "benchmark/run_tests.py" "${version}"
    
    # TODO: Figure out a good way to stop the VPNs. https://docs.python.org/3/library/atexit.html to undo VPN configuration?
    docker exec -itd client-10.9.0.5 pkill python3
    docker exec -itd server-router pkill python3
done

# Shut down containers once benchmarking is complete.
docker compose kill
docker compose down