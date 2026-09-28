FROM alpine:3.20
ADD ./src /app/src
ADD https://example.com/tool.tar.gz /tmp/tool.tar.gz
USER guest
CMD ["/bin/sh"]
