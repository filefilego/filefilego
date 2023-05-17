FROM ubuntu@sha256:dfd64a3b4296d8c9b62aa3309984f8620b98d87e47492599ee20739e8eb54fbf

RUN apt update && apt install nano

COPY cmd/filefilego/filefilego filefilego
COPY data data

RUN ./filefilego address create_node_key admin

VOLUME [ "/root/.filefilego_data/" ]

EXPOSE 8090

# ENTRYPOINT ["./filefilego"]
