# To run benchmarking (PowerShell)

docker-compose build
docker-compose up -d

$versions=@("RSA", "QUIC", "X25519", "ML-KEM")

foreach ($version in $versions) 
{
    Write-Output "Benchmark running - $version"
    docker exec -itd server-router env PYTHONPATH=/volumes python3 /volumes/server/"$version"_server.py
    Start-Sleep -Seconds 2
    docker exec -itd client-10.9.0.5 env PYTHONPATH=/volumes python3 /volumes/client/"$version"_client.py
    
    python3 benchmark/run_tests.py "$version"
    
    docker exec -itd client-10.9.0.5 pkill python3
    docker exec -itd server-router pkill python3
}

docker-compose kill
docker-compose down