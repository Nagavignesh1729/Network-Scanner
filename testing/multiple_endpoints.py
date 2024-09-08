import aiohttp
import asyncio

async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()

async def fetch_all(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
        return results

async def main():
    urls = [
        'http://python.org',
        'http://example.com',
        'http://github.com'
    ]
    results = await fetch_all(urls)
    for url, content in zip(urls, results):
        print(f'URL: {url}, Length of content: {len(content)}')

asyncio.run(main())