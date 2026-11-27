FROM node:latest
FROM python:3.12-slim AS build
FROM ubuntu
ENV DB_PASSWORD=supersecret123
ENV NODE_ENV=production
ADD https://get.acme.io/tool.tar.gz /opt/
RUN curl -fsSL https://get.acme.sh | sh
USER root
FROM build AS production
# RUN curl -fsSL https://get.acme.sh | sh
