import sys
sys.path.insert(0, '.')
from server_new import app

with app.test_client() as c:
    c.post('/api/collect', json={'mode': 'standard', 'sources': [], 'confidences': []})
    r = c.get('/api/events')
    data = r.get_json()
    sources = set(e['source'] for e in data['events'])
    print('All Unique sources:', sorted(sources))
