from __future__ import annotations
import json, urllib.request

class OpenAICompatibleProvider:
    def __init__(self,name,base_url,model,api_key=''):
        self.name=name; self.base_url=base_url.rstrip('/'); self.model=model; self.api_key=api_key

    def chat(self, messages, temperature=0, timeout=90):
        payload={'model':self.model,'messages':messages,'temperature':temperature}
        req=urllib.request.Request(self.base_url+'/chat/completions',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        if self.api_key: req.add_header('Authorization','Bearer '+self.api_key)
        with urllib.request.urlopen(req,timeout=timeout) as r:
            data=json.loads(r.read().decode())
        return data['choices'][0]['message']['content']
