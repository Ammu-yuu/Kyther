"""Phone number intelligence — fully offline. Keyless, no external site.

Reimplements the core of PhoneInfoga's local analysis using Google's
libphonenumber (the `phonenumbers` package): validity, country/region, carrier,
line type, and timezones — computed from the number itself, no network call.
"""
from __future__ import annotations

import phonenumbers
from phonenumbers import PhoneNumberFormat, carrier, geocoder
from phonenumbers import timezone as pn_timezone

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register

_LINE_TYPE = {
    0: "fixed line", 1: "mobile", 2: "fixed line or mobile", 3: "toll free",
    4: "premium rate", 5: "shared cost", 6: "VoIP", 7: "personal number",
    8: "pager", 9: "UAN", 10: "voicemail", 99: "unknown",
}


@register
class PhoneIntel(Analyzer):
    name = "phone_intel"
    description = "Offline phone intelligence: country, carrier, line type, timezone."
    accepts = {EntityType.PHONE}

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()

        num = None
        assumed_region = None
        # E.164 (with +) parses regionless; otherwise try common regions.
        for region in (None, "US", "GB", "IN", "CA"):
            try:
                candidate = phonenumbers.parse(entity.value, region)
            except phonenumbers.NumberParseException:
                continue
            if phonenumbers.is_possible_number(candidate):
                num = candidate
                assumed_region = region
                break

        if num is None:
            result.error = "could not parse phone number"
            return result

        valid = phonenumbers.is_valid_number(num)
        data = {
            "valid": valid,
            "e164": phonenumbers.format_number(num, PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(num, PhoneNumberFormat.INTERNATIONAL),
            "country_code": num.country_code,
            "location": geocoder.description_for_number(num, "en") or None,
            "region": phonenumbers.region_code_for_number(num),
            "carrier": carrier.name_for_number(num, "en") or None,
            "line_type": _LINE_TYPE.get(phonenumbers.number_type(num), "unknown"),
            "timezones": list(pn_timezone.time_zones_for_number(num)),
        }
        if assumed_region and not entity.value.startswith("+"):
            data["note"] = f"no country code given — assumed region {assumed_region}"

        result.findings.append(
            Finding(
                self.name, entity,
                f"{data['line_type']} · {data['location'] or data['region'] or 'unknown region'}"
                + ("" if valid else " (not a valid number)"),
                data=data,
            )
        )
        return result
