import asyncio
import aiohttp


class EventLogger:
    def __init__(self):
        self.event_id = 0

    async def async_report_event(self, event):
        url = "https://seclab.fiw.fhws.de/input/"
        headers = {
            'Content-Type': 'application/json',
        }
        async with aiohttp.ClientSession() as session:
            post_tasks = [self.do_post(session, url, headers, event)]
            await asyncio.gather(*post_tasks)

    async def do_post(self, session, url, headers, event):
        async with session.post(url, data=event, headers=headers) as response:
            data = await response.text()
            print("-> Sent event %s" % event)
            print(data)
