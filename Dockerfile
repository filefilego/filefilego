FROM ubuntu:20.04

COPY cmd/filefilego/filefilego filefilego

RUN apt update && apt install nano

RUN ./filefilego address create_node_key admin

VOLUME [ "/root/.filefilego_data/" ]

EXPOSE 8090

# ENTRYPOINT ["./filefilego"]
