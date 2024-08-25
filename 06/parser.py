import json
from datetime import datetime


def parse_file(file_name: str) -> dict | None:
    with open(file_name, 'r') as f:
        content = json.load(f)
    cve_meta_data = content["cveMetadata"]
    if cve_meta_data['state'] != 'PUBLISHED':
        # print('Not published:', file_name)
        return None
    date_published = cve_meta_data.get('datePublished')
    if date_published is None:
        # print('datePublished is absent:', file_name)
        return None
    result = {
        'date_published': datetime.fromisoformat(date_published),
        'date_updated': datetime.fromisoformat(cve_meta_data['dateUpdated']),
        'id': cve_meta_data['cveId']
    }
    containers = content['containers']
    cna = containers['cna']
    result['title'] = cna.get('title', 'n/a')
    nodes = cna['descriptions']
    descriptions = []
    for node in nodes:
        text = node.get('value') or node.get('description')
        if text:
            descriptions.append({
                'lang': node['lang'],
                'text': text
            })
    result['descriptions'] = descriptions
    problem_types = []
    nodes = cna.get('problemTypes', [])
    for node in nodes:
        sub_nodes = node.get('descriptions', [])
        for sub_node in sub_nodes:
            text = sub_node.get('description')
            if text and text != 'n/a':
                problem_types.append({
                    'lang': sub_node['lang'],
                    'text': text
                })
    result['problem_types'] = problem_types
    nodes = cna.get('references', [])
    result['references'] = [
        {
            'name': node.get('name', 'n/a'),
            'url': node['url'],
            # 'tags': node.get('tags', [])
        } for node in nodes
    ]
    return result
