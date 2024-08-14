import asyncio
import random

THINKING_TIME = 2, 5
EATING_TIME = 2, 5
PHILOSOPHER_COUNT = 5
FORK_COUNT = PHILOSOPHER_COUNT
DAILY_CYCLE = 3
MONITORING_INTERVAL = 1


class State:
    INACTIVE = 'inactive'
    THINKING = 'thinking'
    WAITING_FORKS = 'waiting'
    EATING = 'eating'


class Fork:
    def __init__(self, number: int):
        self.owner = 0
        self.number = number
        self._initialize()

    def _initialize(self):
        """Low-level method, must be overridden: initialize internal async object"""
        pass

    async def acquire(self, owner_id: int):
        await self._acquire()
        self.owner = owner_id
        print('Member', owner_id, 'acquired the fork', self.number)

    async def release(self):
        await self._release()
        owner_id, self.owner = self.owner, 0
        print('Member', owner_id, 'released the fork', self.number)

    async def _acquire(self):
        """Low-level method, must be overridden """
        pass

    async def _release(self):
        """Low-level method, must be overridden """
        pass


class QueueFork(Fork):
    def _initialize(self):
        self.queue = asyncio.Queue(1)

    async def _acquire(self):
        await self.queue.join()
        await self.queue.put(self.owner)

    async def _release(self):
        await self.queue.get()
        self.queue.task_done()


class LockFork(Fork):
    def _initialize(self):
        self.lock = asyncio.Lock()

    async def _acquire(self):
        await self.lock.acquire()

    async def _release(self):
        self.lock.release()


class EventFork(Fork):
    def _initialize(self):
        self.event = asyncio.Event()
        self.event.set()  # Initial state of a fork is "free"

    async def _acquire(self):
        await self.event.wait()
        self.event.clear()

    async def _release(self):
        self.event.set()


class Philosopher:

    def __init__(self, number: int, forks: tuple):
        self.state = State.INACTIVE
        self.number = number
        self.forks = forks
        self.meal_count = 0

    async def acquire_forks(self):
        """Get exclusive access to the both forks"""

        self.set_state(State.WAITING_FORKS)
        await asyncio.wait([
            asyncio.create_task(fork.acquire(self.number)) for fork in self.forks
        ], return_when=asyncio.ALL_COMPLETED)

    def set_state(self, new_state):
        old_state, self.state = self.state, new_state
        print("Member", self.number, f"changed state from '{old_state}' to '{self.state}'")

    async def release_forks(self):
        """Release exclusive access to both forks"""

        for fork in self.forks:
            await fork.release()

    async def eating(self):
        self.set_state(State.EATING)
        duration = random.randint(*EATING_TIME)
        await asyncio.sleep(duration)
        self.meal_count += 1

    async def thinking(self):
        self.set_state(State.THINKING)
        duration = random.randint(*THINKING_TIME)
        await asyncio.sleep(duration)

    async def daily_life(self):
        """Task describes "daily life" of each philosopher """

        try:
            for _ in range(DAILY_CYCLE):
                await self.thinking()
                await self.acquire_forks()
                await self.eating()
                await self.release_forks()
        finally:
            self.set_state(State.INACTIVE)
        return self.meal_count


class PhilosopherClub:

    def __init__(self, fork_class):
        self.forks = [fork_class(i+1) for i in range(FORK_COUNT)]
        fork_pairs = [
            (self.forks[i], self.forks[(i + 1) % FORK_COUNT]) for i in range(FORK_COUNT)
        ]
        self.members = [
            Philosopher(i+1, fork_pairs[i]) for i in range(PHILOSOPHER_COUNT)
        ]

    async def monitoring(self):
        done = 0
        while done < len(self.members):
            await asyncio.sleep(MONITORING_INTERVAL)
            states = [m.state for m in self.members]
            done = states.count(State.INACTIVE)
            print('States are: ', ', '.join(states))
            print('Forks owners: ', ', '.join([str(f.owner) for f in self.forks]))
        for m in self.members:
            print(f'Member {m.number} ate {m.meal_count} times')


    async def daily_life(self):
        """Task describes "daily life" of all philosophers together"""

        tasks = [
            asyncio.create_task(p.daily_life(), name=str(p.number)) for p in self.members
        ]
        monitor_task = asyncio.create_task(self.monitoring())
        await asyncio.gather(monitor_task, *tasks)


if __name__ == '__main__':
    methods = [LockFork, EventFork, QueueFork]
    method = random.choice(methods)
    print('Using', method.__name__)
    club = PhilosopherClub(method)
    asyncio.run(club.daily_life())
