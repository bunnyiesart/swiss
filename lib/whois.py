import whois as python_whois


class WHOISClient:
    def lookup(self, domain: str) -> dict:
        try:
            w = python_whois.whois(domain)
            def _first(v):
                if isinstance(v, list):
                    return str(v[0]) if v else None
                return str(v) if v else None

            return {
                "source":          "whois",
                "domain":          _first(w.get("domain_name")),
                "registrar":       _first(w.get("registrar")),
                "creation_date":   _first(w.get("creation_date")),
                "expiration_date": _first(w.get("expiration_date")),
                "updated_date":    _first(w.get("updated_date")),
                "name_servers":    [str(ns).lower() for ns in (w.get("name_servers") or [])[:5]],
                "status":          _first(w.get("status")),
                "org":             _first(w.get("org")),
                "country":         _first(w.get("country")),
                "emails":          [str(e) for e in (w.get("emails") or [])[:3]],
            }
        except Exception as e:
            return {"source": "whois", "error": str(e)}
