# syntax=docker/dockerfile:1

FROM python:3.9-alpine

COPY . .

RUN apk update
RUN apk add git
RUN cd /
RUN git clone https://github.com/ferelarg/Seplos3MQTT
RUN pip3 install -r /Seplos3MQTT/requirements.txt

CMD [ "python3", "/Seplos3MQTT/seplos3mqtt.py"]

