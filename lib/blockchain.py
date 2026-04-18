import re

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_TX_RE = re.compile(r"^[a-fA-F0-9]{64}$")
BASE = "https://blockchain.info"


class BlockchainClient:
    def __init__(self):
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def lookup(self, address: str) -> dict:
        try:
            if _TX_RE.match(address):
                return self._lookup_tx(address)
            return self._lookup_address(address)
        except Exception as e:
            return {"source": "blockchain", "error": str(e)}

    def _lookup_address(self, address: str) -> dict:
        r = self._session.get(f"{BASE}/rawaddr/{address}", params={"limit": 10}, timeout=15)
        r.raise_for_status()
        d = r.json()
        txs = d.get("txs", [])
        return {
            "source":          "blockchain",
            "type":            "address",
            "address":         address,
            "final_balance":   d.get("final_balance"),
            "total_received":  d.get("total_received"),
            "total_sent":      d.get("total_sent"),
            "n_tx":            d.get("n_tx"),
            "recent_txs": [
                {
                    "hash":        tx.get("hash"),
                    "time":        tx.get("time"),
                    "result":      tx.get("result"),
                    "fee":         tx.get("fee"),
                }
                for tx in txs[:10]
            ],
        }

    def _lookup_tx(self, tx_hash: str) -> dict:
        r = self._session.get(f"{BASE}/rawtx/{tx_hash}", timeout=15)
        r.raise_for_status()
        d = r.json()
        return {
            "source":        "blockchain",
            "type":          "transaction",
            "hash":          d.get("hash"),
            "time":          d.get("time"),
            "block_height":  d.get("block_height"),
            "fee":           d.get("fee"),
            "size":          d.get("size"),
            "inputs_count":  len(d.get("inputs", [])),
            "outputs_count": len(d.get("out", [])),
        }
