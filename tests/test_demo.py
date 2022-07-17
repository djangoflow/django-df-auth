
def test_example(client):
    result = client.get('/demo/').json()
    assert result == {'demo': 'demo'}
