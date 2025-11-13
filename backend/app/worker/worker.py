import redis
from rq import Worker, Queue, Connection

# Define which queues this worker should listen to
listen = ['default']

# Connect to the same Redis server
redis_conn = redis.Redis(host='localhost', port=6379)

if __name__ == '__main__':
    with Connection(redis_conn):
        print("Starting RQ Worker... Listening for jobs on 'default' queue.")
        # Create a new worker and tell it which queues to 'listen' to
        worker = Worker(map(Queue, listen))
        # Start the worker. This will run forever until you press Ctrl+C
        worker.work()