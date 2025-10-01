import sys, subprocess, time, csv, re, os

# VPN configuration
VERSION = sys.argv[1]
VPN_TARGET_IP = "192.168.60.7"
VPN_CLIENT_CONTAINER = "client-10.9.0.5"
VPN_SERVER_CONTAINER = "server-router"
PRIVATE_HOST_CONTAINER = "host-192.168.60.7"
LOG_FILE = f"benchmark/results/{VERSION}_vpn_benchmark_results.csv"


def run_cmd(cmd, capture_output=False):
    return subprocess.run(cmd, shell=True, text=True, capture_output=capture_output)


def parse_ping_output(output):
    match = re.search(r"min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output)
    if match:
        return [float(match.group(i)) for i in range(1, 5)]
    return [None] * 4


def parse_iperf_output(output):
    try:
        sender_match = re.search(
            r"\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+[\d\.]+\s+\w+Bytes\s+([\d\.]+\s+Mbits)\/sec\s+\d*\s+sender", output)
        if not sender_match:
            sender_match = re.search(
                r"\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+[\d\.]+\s+\w+Bytes\s+([\d\.]+\s+Gbits)\/sec\s+\d*\s+sender",
                output)
        receiver_match = re.search(
            r"\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+[\d\.]+\s+\w+Bytes\s+([\d\.]+\s+Mbits)\/sec\s+receiver", output)
        if not receiver_match:
            receiver_match = re.search(
                r"\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+[\d\.]+\s+\w+Bytes\s+([\d\.]+\s+Gbits)\/sec\s+receiver",
                output)

        if sender_match and receiver_match:
            sender = sender_match.group(1)
            receiver = receiver_match.group(1)
            return sender, receiver
        else:
            print("[!] Could not find both sender and receiver in iperf output.")
            print(output)
            return None
    except Exception as e:
        print(f"[!] Exception while parsing iperf output: {e}")
        return None


def log_result(test_type, metric, value):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([test_type, metric, value])


def run_ping_test():
    print("Running Ping test.")
    result = run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} ping -c 5 {VPN_TARGET_IP}', capture_output=True)
    time.sleep(3)
    metrics = parse_ping_output(result.stdout)
    for name, value in zip(["min", "avg", "max", "mdev"], metrics):
        log_result("ping", name, value)


def run_iperf_tcp_test():
    print("Running iperf TCP test.")
    run_cmd(f'docker exec {PRIVATE_HOST_CONTAINER} pkill iperf3 || true')
    run_cmd(f'docker exec -d {PRIVATE_HOST_CONTAINER} iperf3 -s')
    time.sleep(2)
    result = run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} iperf3 -c {VPN_TARGET_IP} -t 10', capture_output=True)
    check_cpu_memory()
    time.sleep(12)
    throughput = parse_iperf_output(result.stdout)
    log_result("iperf3-tcp", "throughput_mbps", throughput)


def run_iperf_udp_test():
    print("Running iperf UDP test.")
    run_cmd(f'docker exec {PRIVATE_HOST_CONTAINER} pkill iperf3 || true')
    run_cmd(f'docker exec -d {PRIVATE_HOST_CONTAINER} iperf3 -s')
    time.sleep(2)
    result = run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} iperf3 -c {VPN_TARGET_IP} -u -b 500M -t 10', capture_output=True)
    check_cpu_memory()
    time.sleep(12)
    log_result("iperf3-udp", "raw_output", result.stdout.strip())


def run_concurrent_load():
    print("Running concurrent load test.")
    ping_proc = subprocess.Popen(
        f'docker exec {VPN_CLIENT_CONTAINER} ping -i 0.2 -c 20 {VPN_TARGET_IP}',
        shell=True
    )
    try:
        result = run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} iperf3 -c {VPN_TARGET_IP} -t 5', capture_output=True)
        time.sleep(12)
        throughput = parse_iperf_output(result.stdout)
        ping_proc.terminate()
        log_result("concurrent", "throughput_mbps", throughput)
    finally:
        ping_proc.terminate()


def check_cpu_memory():
    print("Checking CPU and Memory.")
    result = run_cmd(
        f'docker exec {VPN_SERVER_CONTAINER} ps -C python3 -o rss,vsz,%cpu,%mem,cmd',
        capture_output=True
    )
    log_result("resource", "cpu_mem_info", result.stdout.strip())


def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["test_type", "metric", "value"])

    print("Log setup.")


def main():
    print(f"Starting VPN Benchmarking ({VERSION})")
    init_log()

    check_cpu_memory()
    run_ping_test()
    run_iperf_tcp_test()
    run_iperf_udp_test()
    run_concurrent_load()

    print(f"\nBenchmark Complete. Results saved in: {LOG_FILE}\n")


if __name__ == "__main__":
    main()
