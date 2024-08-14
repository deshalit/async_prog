import asyncio
import random

THINKING_TIME = 2, 5
EATING_TIME = 2, 5
PHILOSOPHER_COUNT = 5
FORK_COUNT = PHILOSOPHER_COUNT
DAILY_CYCLE = 10


class Philosophers:
    async def acquire_fork(self, fork, philosopher: int):
        """Get exclusive access to the fork"""
        pass

    async def acquire_forks(self, forks: tuple, philosopher: int):
        """Get exclusive access to the both forks"""
        await asyncio.gather(*[self.acquire_fork(fork, philosopher) for fork in forks])
        print(f'Philisopher {philosopher} has acquired both forks')

    def create_fork(self):
        """Create a "fork" synchronization object """
        pass

    @staticmethod
    async def eating(philosopher: int):
        duration = random.randint(*EATING_TIME)
        print(f'Philisopher {philosopher} is eating')
        await asyncio.sleep(duration)

    @staticmethod
    async def thinking(philosopher: int):
        duration = random.randint(*THINKING_TIME)
        print(f'Philisopher {philosopher} is thinking')
        await asyncio.sleep(duration)

    async def release_fork(self, fork, philosopher: int):
        """Release exclusive access to the fork"""
        pass

    async def release_forks(self, forks: tuple, philosopher: int):
        """Release exclusive access to both forks"""
        for fork in forks:
            await self.release_fork(fork, philosopher)
        print(f'Philisopher {philosopher} has released both forks')

    async def philosopher(self, number: int, forks):
        """Task describes "daily life" of each philosopher """
        meals = 0
        try:
            for _ in range(DAILY_CYCLE):
                await self.thinking(number)
                await self.acquire_forks(forks, number)
                await self.eating(number)
                meals += 1
                await self.release_forks(forks, number)
        finally:
            print(f'Pholosopher #{number} ate {meals} times')

    async def daily_life(self):
        """Task describes "daily life" of all philosophers together"""
        forks = [self.create_fork() for _ in range(FORK_COUNT)]
        tasks = []
        for i, fork in enumerate(forks, 1):
            fork_pair = forks[i-1], forks[i % FORK_COUNT]
            tasks.append(
                asyncio.create_task(self.philosopher(i, fork_pair))
            )
        await asyncio.gather(*tasks)


class PhilosophersEvent(Philosophers):
    async def acquire_fork(self, fork, philosopher: int):
        await fork.wait()
        fork.clear()

    def create_fork(self):
        fork = asyncio.Event()
        fork.set()  # Initial state of a fork is "free"
        return fork

    async def release_fork(self, fork, philosopher: int):
        fork.set()


class PhilosophersLock(Philosophers):
    async def acquire_fork(self, fork, philosopher: int):
        await fork.acquire()

    def create_fork(self):
        return asyncio.Lock()

    async def release_fork(self, fork, philosopher: int):
        fork.release()


class PhilosophersQueue(Philosophers):
    async def acquire_fork(self, fork, philosopher: int):
        await fork.join()
        await fork.put(philosopher)

    def create_fork(self):
        return asyncio.Queue(1)

    async def release_fork(self, fork, philosopher: int):
        await fork.get()
        fork.task_done()


if __name__ == '__main__':
    methods = [PhilosophersLock, PhilosophersEvent, PhilosophersQueue]
    method = random.choice(methods)
    print('Using', method.__name__)
    asyncio.run(method().daily_life())
