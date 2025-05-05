from django_q.tasks import async_task
import logging, os
import requests, json


fast_api_server = os.getenv('CD_FAST_API_SERVER')

logger = logging.getLogger(__name__)
def my_periodic_function():
    # Your periodic task logic goes here
    logger.info("Running my periodic function")
    response = requests.post(fast_api_server+'/send_notifications/')
    print(response.text)
    print("Running my periodic function")