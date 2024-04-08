# syntax=docker/dockerfile:1

FROM python:3.9-alpine

COPY . /workspace

RUN apk update
RUN pip3 install -r /workspace/requirements.txt

CMD [ "python3", "/workspace/seplos3mqtt.py"]
