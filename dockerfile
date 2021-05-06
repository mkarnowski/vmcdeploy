############################################################
# Dockerfile to build python avi-monitor script container
# Based on ubuntu:18.04
############################################################

# Set the base image to alpine:edge
FROM ubuntu:18.04

# Set the working directory
WORKDIR /usr/src/avideploy

# File Author / Maintainer
MAINTAINER matt.karnowski@gmail.com


################## BEGIN INSTALLATION ######################

# Set Docker environment variable
ENV EN_DOCKER=True


# Install python requirements
RUN apt update && apt install -y python3-pip sshpass
RUN pip3 install --no-cache-dir pip --upgrade
RUN pip3 install --no-cache-dir requests pyyaml netaddr 


# Copy files to directory
COPY "vmc-deployment-container.py" "/usr/src/avideploy/vmc-deployment-container.py"
COPY "govc" "/usr/src/avideploy/govc"
COPY "controller-20.1.5.ova" "/usr/src/avideploy/controller-20.1.5.ova"


# forward request and error logs to docker log collector
RUN ln -sf /dev/stdout /var/log/avideployment.log \
	&& ln -sf /dev/stderr /var/log/avideployment.log


# Execute script
CMD ["python3", "/usr/src/avideploy/vmc-deployment-container.py"]