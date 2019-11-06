import requests
d = {'mail': 'test@oisf.net'}
requests.post("http://localhost:8000", data=d)
