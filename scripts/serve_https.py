from __future__ import annotations
import argparse, ssl
import sys
from pathlib import Path
import uvicorn
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8000);args=parser.parse_args()
    config=uvicorn.Config('backend.app.main:app',host=args.host,port=args.port,ssl_keyfile='keys/server-key.pem',ssl_certfile='certificates/server.pem',ssl_ciphers='ECDHE-ECDSA-AES256-GCM-SHA384',log_level='info')
    config.load()
    if not config.ssl: raise RuntimeError('TLS context was not created')
    config.ssl.minimum_version=ssl.TLSVersion.TLSv1_2
    config.ssl.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
    uvicorn.Server(config).run()
if __name__=='__main__': main()
