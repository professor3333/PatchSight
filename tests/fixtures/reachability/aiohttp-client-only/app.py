import aiohttp


async def fetch(url):
    async with aiohttp.ClientSession() as session, session.get(url) as response:
        return await response.text()
