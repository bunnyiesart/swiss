from ua_parser import user_agent_parser


class UserAgentParser:
    def parse(self, ua_string: str) -> dict:
        try:
            parsed = user_agent_parser.Parse(ua_string)
            ua = parsed.get("user_agent", {})
            os = parsed.get("os", {})
            device = parsed.get("device", {})

            browser_version = ".".join(
                v for v in [ua.get("major"), ua.get("minor"), ua.get("patch")] if v
            )
            os_version = ".".join(
                v for v in [os.get("major"), os.get("minor"), os.get("patch")] if v
            )

            family = device.get("family", "")
            is_mobile = family not in ("Other", "Spider") and bool(family)
            is_bot = ua.get("family", "").lower() in ("bot", "spider", "crawler") or \
                     device.get("family", "").lower() in ("spider",)

            return {
                "source":          "useragent",
                "browser_family":  ua.get("family"),
                "browser_version": browser_version or None,
                "os_family":       os.get("family"),
                "os_version":      os_version or None,
                "device_family":   device.get("family"),
                "device_brand":    device.get("brand"),
                "device_model":    device.get("model"),
                "is_mobile":       is_mobile,
                "is_bot":          is_bot,
            }
        except Exception as e:
            return {"source": "useragent", "error": str(e)}
