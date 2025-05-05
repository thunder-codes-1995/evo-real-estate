# set base image (host OS)
FROM python:3.10

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update
RUN apt-get install -y build-essential git

#RUN apt-get install -y mongodb-clients 
RUN pip3 install -v awscli==1.29.50
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


# set the working directory in the container
WORKDIR /app

#RUN git clone https://github.com/mrjbq7/ta-lib.git

#RUN pwd
#RUN cd /code/ta-lib/ && python setup.py install
# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip install -r requirements.txt

RUN pwd
#ARG ENV_VARIABLE=pr

# copy the content of the local src directory to the working directory
COPY ./evo-prop-sso /app/
#COPY jenkins_ansible/envs/sso/env_$ENV_VARIABLE /app/.env
# Run database migrations and collect static files
#RUN python manage.py migrate
#RUN python manage.py collectstatic --noinput

EXPOSE 8002

#CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
CMD ["uvicorn", "sso.asgi:application", "--host", "0.0.0.0", "--port", "8002"]
