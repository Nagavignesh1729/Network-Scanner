import asyncio

async def task(name, delay):
    print(f'{name} started')
    await asyncio.sleep(delay)
    print(f'{name} completed')
    return f'{name} result'

async def main():
    tasks = [task(f'Task {i}', i) for i in range(1, 4)]
    results = await asyncio.gather(*tasks)
    print('All tasks completed')
    print(results)

asyncio.run(main())