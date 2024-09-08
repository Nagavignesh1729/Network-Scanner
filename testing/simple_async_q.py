import asyncio

async def worker(queue):
    while True:
        task = await queue.get()
        if task is None:
            break
        print(f'Working on {task}')
        await asyncio.sleep(1)  # Simulate work
        queue.task_done()

async def main():
    queue = asyncio.Queue()
    workers = [asyncio.create_task(worker(queue)) for _ in range(3)]

    for i in range(10):
        await queue.put(f'Task {i}')

    await queue.join()
    for _ in workers:
        await queue.put(None)  # Stop signal for workers

    await asyncio.gather(*workers)

asyncio.run(main())