FROM almalinux:latest

# Install Spire dependencies
RUN dnf install -y dnf-plugins-core
RUN dnf config-manager --set-enabled crb
RUN dnf install -y openssl-devel flex byacc qt5-devel cmake python git libyaml-devel libtool gdb valgrind vim make gcc iproute-tc

# Install debugging tools

# Copy source files
COPY . /app/spire
WORKDIR /app/spire

# # Install libcyaml from source
# RUN git clone https://github.com/tlsa/libcyaml.git /tmp/libcyaml && \
#     cd /tmp/libcyaml && \
#     make && make install && \
#     ldconfig

# RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig

# Build Spire core
RUN make reconfiguration

# Run setup during buildmake 
# RUN python3 /app/spire/check_keys.py && \
#     cd /app/spire/example_conf && ./install_conf.sh conf_4

# RUN dnf debuginfo-install -y glibc-2.34-168.el9_6.14.alma.1.x86_64 libyaml-0.2.5-7.el9.x86_64 openssl-libs-3.2.2-6.el9_5.1.x86_64 zlib-1.2.11-40.el9.x86_64

# COPY start_spines.py /app/spire/start_spines.py

# Set entrypoint to python script
ENTRYPOINT ["python3", "/app/spire/start_spines.py"]

