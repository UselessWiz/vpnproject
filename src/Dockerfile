FROM handsonsecurity/seed-ubuntu:large

# Installs  all requirements to build liboqs, as well as python 3.9.
RUN apt-get update && apt-get install -y python3.9 python3-pip iperf3 git astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

# LibOQS-Python needs python 3.9 or higher, so we symlink it to python3 so python defaults to 3.9.
RUN ln -sf /usr/bin/python3.9 /usr/bin/python3

# Builds other python requirements.
COPY requirements.txt /requirements.txt
RUN pip3 install --no-cache-dir -r /requirements.txt

# LibOQS-Python does not have a package on the pip respository. It has to be installed manually.
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python

# Runs a test script after instaling the package to download the actual OQS library.
RUN pip3 install /liboqs-python && python3 /liboqs-python/examples/kem.py



