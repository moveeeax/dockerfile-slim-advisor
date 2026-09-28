FROM debian:12-slim
RUN apt-get update
RUN apt-get install -y curl ca-certificates
COPY requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt
USER app
CMD ["curl", "--version"]
