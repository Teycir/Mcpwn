"""Subscription flooding tests""
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor


class SubscriptionFloodTest:
    """Test resource exhaustion via subscriptions"""
    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, count=1000, parallel=True):
        """Execute subscription flood test"""
        if parallel:
            return self._run_parallel(count)
        return self._run_sequential(count)

    def _run_sequential(self, count):
        """Sequential flood (original behavior)"""
        start = time.time()
        for i in range(count):
            self.pentester.send("resources/subscribe",
                                {"uri": f"file:///{i}.txt"})
        elapsed = time.time() - start
        return {"count": count, "elapsed": elapsed, "rate": count/elapsed}

    def _run_parallel(self, count):
        """Parallel flood using thread pool"""
        def send_sub(i):
            self.pentester.send("resources/subscribe",
                                {"uri": f"file:///{i}.txt"})

        start = time.time()
        with ThreadPoolExecutor(max_workers=50) as executor:
            list(executor.map(send_sub, range(count)))
        elapsed = time.time() - start

        return {"count": count, "elapsed": elapsed, "rate": count/elapsed}
