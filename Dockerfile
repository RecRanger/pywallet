# Use an older version of Ubuntu that supports Python 2
FROM ubuntu:16.04

# Avoiding user interaction with tzdata
ENV DEBIAN_FRONTEND=noninteractive

# Update and install dependencies
RUN apt-get update && \
    apt-get install -y build-essential python-dev python-bsddb3 git

# Clone the pywallet repository
# RUN git clone https://github.com/RecRanger/pywallet /pywallet
COPY ./src/pywallet/ /pywallet/
COPY ./requirements.txt /pywallet/

RUN apt-get install -y python-pip
RUN pip install -r /pywallet/requirements.txt

# Set the working directory to /pywallet
WORKDIR /pywallet

# Set up an entrypoint to run pywallet.py
ENTRYPOINT ["python", "pywallet.py"]
CMD ["--help"]
