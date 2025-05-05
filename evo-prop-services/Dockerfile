# set base image (host OS)
FROM python:3.10

RUN apt-get update
RUN apt-get install -y build-essential git

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# set the working directory in the container
WORKDIR /app

#RUN git clone https://github.com/mrjbq7/ta-lib.git

#RUN pwd
#RUN cd /code/ta-lib/ && python setup.py install
# copy the dependencies file to the working directory
COPY evo-prop-services/backend/requirements.txt .


# install dependencies
RUN pip install -r requirements.txt

COPY evo-prop-services/backend/requirements.in .
RUN pip install -r requirements.in


RUN pwd
ARG ENV_VARIABLE=pr

# copy the content of the local src directory to the working directory
COPY ./evo-prop-services/backend/ /app/
COPY jenkins_ansible/envs/evo-prop-services/env_$ENV_VARIABLE /app/.env
# Run database migrations and collect static files
#RUN python manage.py migrate
#RUN python manage.py collectstatic --noinput

EXPOSE 8001

#CMD ["python", "main.py"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]