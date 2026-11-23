"""Tests for the expanded, structured Company Footprint."""
from __future__ import annotations

import importlib
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from httpx import ASGITransport

from kyther.analyzers.jobs import _skills
from kyther.analyzers.sec_edgar import _name_matches
from kyther.api import app
from kyther.company import (_profile_score, pivot_links, search_terms,
                            slug_candidates, verify_organisation)

footprint_mod = importlib.import_module("kyther.api.footprint")


class CompanyHelperTests(unittest.TestCase):
    def test_search_terms_include_suffix_free_variants(self):
        terms = search_terms("Acme Corp", ["Acme Limited"], "United States")
        self.assertEqual(terms[0], "Acme Corp")
        self.assertTrue(any("Acme" == t or t.startswith("Acme ") for t in terms))
        self.assertTrue(any("United States" in t for t in terms))

    def test_slug_candidates_from_name_and_domain(self):
        slugs = slug_candidates("Acme Corp", ["acme.io"])
        self.assertEqual(slugs[0], "acme")

    def test_profile_score_rejects_unrelated_wikipedia_hit(self):
        good = _profile_score({"title": "Alias Robotics"}, "Alias Robotics", ["aliasrobotics.com"])
        bad = _profile_score({"title": "Robot (Lost in Space)"}, "Alias Robotics",
                             ["aliasrobotics.com"])
        self.assertGreater(good, 25)
        self.assertLess(bad, 25)

    def test_verify_organisation_requires_a_real_link(self):
        ok, reason = verify_organisation({"title": "Alias Robotics"},
                                         "Alias Robotics")
        self.assertTrue(ok)
        self.assertIn("name matches", reason)

        ok, _ = verify_organisation({"title": "Robot (Lost in Space)"},
                                    "Alias Robotics", ["aliasrobotics.com"])
        self.assertFalse(ok)

        ok, reason = verify_organisation(
            {"login": "something-else", "blog": "https://aliasrobotics.com"},
            "Alias Robotics", ["aliasrobotics.com"],
        )
        self.assertTrue(ok)
        self.assertIn("website", reason)

    def test_pivots_are_labelled_as_manual_lookups(self):
        links = pivot_links(["Acme Corp"], ["acme.com"], "Acme Corp")
        self.assertTrue(links)
        labels = [link["label"] for link in links]
        for label in ("Search LinkedIn", "Search GitHub", "Search Wikidata"):
            self.assertIn(label, labels)
        for jargon in ("crt.sh", "Wayback", "Google docs"):
            self.assertFalse(any(jargon in label for label in labels))
        for link in links:
            self.assertTrue(link["url"].startswith("https://"))
            self.assertNotIn("javascript", link["url"])
            self.assertTrue(link.get("manual"))
            self.assertNotIn("manual", link["group"])

    def test_sec_hits_must_name_the_company(self):
        self.assertTrue(_name_matches("Acme Corp Inc.", "Acme Corp"))
        self.assertFalse(_name_matches("Telefonica S A (TEF)", "Alias Robotics"))

    def test_job_descriptions_reveal_tech_stack(self):
        skills = _skills("<p>We run <b>Kubernetes</b> on AWS with PostgreSQL.</p>")
        self.assertEqual(skills, ["AWS", "Kubernetes", "PostgreSQL"])


class FootprintApiTests(unittest.IsolatedAsyncioTestCase):
    async def _client(self):
        transport = ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url="http://testserver")

    async def test_post_accepts_structured_company_intake(self):
        payload = {
            "ok": True, "name": "Acme", "target": "Acme",
            "domains": ["acme.com"], "pivots": [],
        }
        with patch.object(footprint_mod, "_build_footprint",
                          new=AsyncMock(return_value=payload)) as build:
            async with await self._client() as c:
                response = await c.post("/api/footprint", json={
                    "target": "Acme", "name": "Acme", "domains": ["acme.com"],
                    "aliases": ["Old Acme"], "country": "US", "deep": True,
                })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["domains"], ["acme.com"])
        build.assert_awaited_once_with(
            "Acme", "Acme", ["acme.com"], ["Old Acme"], "US", True
        )

    async def test_legacy_get_still_works(self):
        with patch.object(footprint_mod, "_build_footprint",
                          new=AsyncMock(return_value={"ok": True})) as build:
            async with await self._client() as c:
                response = await c.get("/api/footprint?target=acme.com")
        self.assertEqual(response.status_code, 200)
        build.assert_awaited_once_with("acme.com", "", None, None, "", False)

    async def test_deep_scan_collects_public_identity_sources(self):
        profile = {
            "title": "Acme", "summary": "A company.", "url": "https://en.wikipedia.org/wiki/Acme",
            "wikidata_id": "Q1", "facts": {"Industry": ["Software"]},
        }
        with patch.object(footprint_mod, "_analyzer", return_value=None), \
             patch.object(footprint_mod, "_resolve_ips", new=AsyncMock(return_value=[])), \
             patch.object(footprint_mod, "wikipedia_profile",
                          new=AsyncMock(return_value=(profile, None))), \
             patch.object(footprint_mod, "wikidata_facts",
                          new=AsyncMock(return_value=({"id": "Q1", "facts": {"Industry": ["Software"]}}, None))), \
             patch.object(footprint_mod, "github_org",
                          new=AsyncMock(return_value=({"login": "acme", "repos": []}, None))), \
             patch.object(footprint_mod, "wayback_summary",
                          new=AsyncMock(return_value=({"domain": "acme.com", "count": 3}, None))):
            out = await footprint_mod._build_footprint(
                name="Acme", domains=["acme.com"], deep=True
            )

        self.assertEqual(out["name"], "Acme")
        self.assertEqual(out["domain"], "acme.com")
        self.assertEqual(out["profile"]["facts"]["Industry"], ["Software"])
        self.assertEqual(out["github"]["login"], "acme")
        self.assertEqual(out["archive"]["count"], 3)
        self.assertTrue(out["pivots"])
        self.assertEqual(out["pivots"], out["manual_lookups"])
        self.assertEqual(out["source_checks"]["linkedin"]["status"], "manual")
        self.assertEqual(out["source_checks"]["wikipedia"]["status"], "verified")
        self.assertEqual(out["source_checks"]["github"]["status"], "verified")

    async def test_unverified_identity_is_never_shown_as_data(self):
        bogus_profile = {"title": "Robot (Lost in Space)",
                         "summary": "a fictional character", "url": "https://example.org/x"}
        bogus_org = {"login": "unrelated-holdings", "name": "Something Else Ltd",
                     "repos": []}
        with patch.object(footprint_mod, "_analyzer", return_value=None), \
             patch.object(footprint_mod, "_resolve_ips", new=AsyncMock(return_value=[])), \
             patch.object(footprint_mod, "wikipedia_profile",
                          new=AsyncMock(return_value=(bogus_profile, None))), \
             patch.object(footprint_mod, "github_org",
                          new=AsyncMock(return_value=(bogus_org, None))), \
             patch.object(footprint_mod, "wayback_summary",
                          new=AsyncMock(return_value=(None, None))):
            out = await footprint_mod._build_footprint(
                name="Alias Robotics", domains=["aliasrobotics.com"], deep=True
            )

        self.assertIsNone(out["profile"])
        self.assertIsNone(out["github"])
        self.assertEqual(out["source_checks"]["wikipedia"]["status"], "unverified")
        self.assertEqual(out["source_checks"]["github"]["status"], "unverified")
        self.assertTrue(any("wikipedia: discarded" in e for e in out["errors"]))
        self.assertTrue(any("github: no organisation verified" in e for e in out["errors"]))
