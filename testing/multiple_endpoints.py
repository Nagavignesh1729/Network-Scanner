import aiohttp
import asyncio

async def fetch(session, url):
    try:
        async with session.get(url, timeout=2) as response:
            return await response.text()
    except asyncio.TimeoutError:
        return f'Timeout for URL: {url}'
    except Exception as e:
        return f'Error for URL: {url} - {str(e)}'

async def main():
    urls = [
        'http://python.org',
        'http://example.com',
        'http://invalid-url'
    ]
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*(fetch(session, url) for url in urls))
        for url, result in zip(urls, results):
            print(f'URL: {url}, Result: {result}')

asyncio.run(main())