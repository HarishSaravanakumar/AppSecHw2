FROM ubuntu:latest

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev

COPY ./requirements.txt /app/requirements.txt

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
WORKDIR /app

COPY . /app

EXPOSE 5000

RUN pip3 install -r /app/requirements.txt
RUN rm -rf /tmp
CMD ["flask", "run", "-h", "0.0.0.0", "-p", "8080"]

