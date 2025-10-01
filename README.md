# VPN Project
VPN implementation in Python for Linux (and potentially other Unix-like operating systems).

Please see the [user documentation PDF](user_documentation.pdf) for a more detailed overview on the VPN and benchmarking.

### Architecture overview
This VPN is deployed in preconfigured Docker containers running Linux across two private networks (Class A and Class C), there is no router or any fancy networking between the two networks. See the diagrams below to understand this structure.
![Diagram of VPN system architecture with VPN on](images/active.png)

![Diagram of VPN system architecture with VPN client off](images/inactive.png)

### Running the VPN
```shell
version="RSA" # Select version, use "RSA", "QUIC", "X25519" or "ML-KEM"

docker-compose build
docker-compose up -d

# Generate RSA keys for RSA version
mkdir keys
openssl genrsa -out keys/RSA/server_private.pem 2048
openssl rsa -in keys/RSA/server_private.pem -outform PEM -pubout -out keys/server_public.pem
openssl genrsa -out keys/RSA/client_private.pem 2048
openssl rsa -in keys/RSA/client_private.pem -outform PEM -pubout -out keys/client_public.pem

# Generate keys for X25519 version
mkdir keys
openssl genpkey -algorithm X25519 -out keys/X25519/x-server_private.pem
openssl pkey -in keys/x-server_private.pem -pubout -out keys/X25519/x-server_public.pem
openssl genpkey -algorithm X25519 -out keys/X25519/x-client_private.pem
openssl pkey -in keys/x-client_private.pem -pubout -out keys/X25519/x-client_public.pem

# Generate keys for ML-KEM version
mkdir keys
python3 tools/keygen.py

# Validate no connectivity between client and internal host
docker exec -it client-10.9.0.5 ping 192.168.60.7

# Start VPN client and server
docker exec -it client-10.9.0.5 env PYTHONPATH=/volumes python3 /volumes/client/${version}_client.py &
docker exec -it server-router env PYTHONPATH=/volumes python3 /volumes/server/${version}_server.py &

# Validate the connectivity between client and internal host
docker exec -it client-10.9.0.5  ping 192.168.60.7
```
Benchmarking needs to be run from the src directory, and should be run on the host machine (not within the containers). It is recommended to create a virtual environment on the machine and run benchmarking using that.

To perform benchmarking, run the `benchmark.sh` or `benchmark.ps1` scripts. 

### Creating a local Wireguard connection for comparison testing
Assumptions:
- Devices are on same local network
- IP addresses are 192.168.55.50 and 192.168.55.51


```ini
# Device 1
[Interface]
PrivateKey = # Put a key here
ListenPort = 51820
Address = 10.0.0.1/24

[Peer]
PublicKey = # Put a key here
AllowedIPs = 10.0.0.2/32
Endpoint = 192.168.55.51:51820
PersistentKeepalive = 25

# Device 2
[Interface]
PrivateKey = # Put a key here
ListenPort = 51820
Address = 10.0.0.2/24

[Peer]
PublicKey = # Put a key here
AllowedIPs = 10.0.0.1/32
Endpoint = 192.168.55.50:51820
PersistentKeepalive = 25
```

## Project Milestones
- [x] Virtual interface created and data encapsulated inside the VPN's UDP packets  
- [x] UDP packet sent by VPN from one device to another  
- [x] Basic UDP client–server communication established; packets can be sent both ways  
- [x] Basic encryption/decryption method implemented for securing network traffic  
- [x] Authentication  
- [x] Performance testing conducted with iperf  
- [x] Functional prototype deployed  
- [x] User guides developed  
- [ ] Technical documentation developed  

## Functional Requirements
- [x] Working prototype developed to align with the client–server model (Jing et al., 1999, p. 30)
- [x] Encryption implemented using asymmetric algorithms like ECDH, ECDSA, and RSA or the newly developed post–quantum ML–DSA, ML-KEM (Australian Cyber Security Centre, 2025, p. 178) or FIPS–203 standard (NIST, 2024) 
- [x] User authentication  
- [x] UDP tunnelling 
- [x] Verbose logging and debugging features
- [x] Virtual interface implemented to facilitate network communication

## Non–Functional Requirements
- [ ] Resource usage kept at a minimum
- [ ] Low–latency
- [x] Adhering to industry–standard encryption protocols
<br>

---

##### References  
  
###### Australian Cyber Security Centre. (2025). *Information security manual (ISM) (March 2025 ed.).* Australian Signals Directorate. https://www.cyber.gov.au/resources-business-and-government/essential-cybersecurity/ism

###### Jing, J., Helal, A. S., & Elmagarmid, A. (1999). *Client-server computing in mobile environments.* ACM Computing Surveys (CSUR), *31(2)*, 117-157. [https://doi.org/10.1145/319806.31981](https://doi.org/10.1145/319806.31981)  

###### National Institute of Standards and Technology (NIST). (2024). *Module-Lattice-Based Key-Encapsulation Mechanism Standard.* [https://doi.org/10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
