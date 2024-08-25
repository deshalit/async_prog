from queries import get_cves_by_published, get_cve_by_id, get_cves_by_updated
from datetime import datetime
import asyncio
import cve_db


async def main():
    async with cve_db.get_session() as session:
        sample_id = 'CVE-2003-5003'
        cve = await get_cve_by_id(session, sample_id)
        print('CVE with id "', sample_id, '" is', cve)
        print('Title:', cve.title)
        print('Published at:', datetime.strftime(cve.date_published, '%d.%m.%Y %H:%M'))
        print('Updated at:', datetime.strftime(cve.date_published, '%d.%m.%Y %H:%M'))
        descriptions = [item for item in await cve.awaitable_attrs.descriptions]
        if descriptions:
            print('Descriptions:')
            for item in descriptions:
                print(f'    lang: {item.lang}, text: "{item.text}"')
        problem_types = [item for item in await cve.awaitable_attrs.problem_types]
        if problem_types:
            print('Problem types:')
            for item in problem_types:
                print(f'    lang: {item.lang}, text: "{item.text}"')
        references = [item for item in await cve.awaitable_attrs.references]
        print('References:')
        for item in references:
            print(f'    name: {item.name}, url: "{item.url}"')

        sample = '2022-03-25T00:00:00Z', '2022-03-29T00:00:00Z'
        date_from = datetime.fromisoformat(sample[0])
        date_to = datetime.fromisoformat(sample[1])

        cves = await get_cves_by_published(session, date_from)
        print('Records with start date_published', sample[0], ':', len(cves))
        for cve in cves:
            assert cve.date_published >= date_from

        cves = await get_cves_by_published(session, date_from, date_to)
        print('Records with date_published between', sample[0], 'and', sample[1], ':', len(cves))
        for cve in cves:
            ok = (cve.date_published >= date_from) and (cve.date_published <= date_to)
            if not ok:
                print(cve.id, 'has', cve.date_published)

        sample = '2022-03-25T00:00:00Z', '2022-03-29T00:00:00Z'
        date_from = datetime.fromisoformat(sample[0])
        date_to = datetime.fromisoformat(sample[1])

        cves = await get_cves_by_updated(session, date_from)
        print('Records with start date_updated', sample[0], ':', len(cves))
        for cve in cves:
            assert cve.date_updated >= date_from

        cves = await get_cves_by_updated(session, date_from, date_to)
        print('Records with date_updated between', sample[0], 'and', sample[1], ':', len(cves))
        for cve in cves:
            ok = (cve.date_updated >= date_from) and (cve.date_updated <= date_to)
            if not ok:
                print(cve.id, 'has', cve.date_updated)


if __name__ == "__main__":
    asyncio.run(main())