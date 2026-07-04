import json

import dns.resolver
import pytest
import requests

import subs


class TestValidateDomain:
    def test_bare_domain(self):
        assert subs.validateDomain("example.com") == "example.com"

    def test_domain_with_scheme(self):
        assert subs.validateDomain("https://example.com/") == "example.com"

    def test_domain_with_port_and_path(self):
        assert subs.validateDomain("https://example.com:8080/foo") == "example.com"

    def test_path_traversal_suffix_is_stripped(self):
        assert subs.validateDomain("example.com/../../etc") == "example.com"

    def test_path_traversal_prefix_is_rejected(self):
        with pytest.raises(ValueError):
            subs.validateDomain("../../etc/example.com")

    @pytest.mark.parametrize("bad", ["", "no-dot", "-example.com", "example-.com", "exa mple.com"])
    def test_invalid_domains_raise(self, bad):
        with pytest.raises(ValueError):
            subs.validateDomain(bad)


class TestIsValidSubdomain:
    @pytest.mark.parametrize("sub", ["www", "api-v2", "_dmarc", "ftp_", "a.b.c"])
    def test_valid(self, sub):
        assert subs.isValidSubdomain(sub) is True

    @pytest.mark.parametrize("sub", ["", "-bad", "bad-", "bad space", "bad/slash"])
    def test_invalid(self, sub):
        assert subs.isValidSubdomain(sub) is False


class TestCheckDNS:
    def test_a_record_only(self, monkeypatch):
        def fake_resolve(name, rtype, lifetime=None):
            if rtype == "A":
                return ["1.2.3.4"]
            raise dns.resolver.NoAnswer()

        monkeypatch.setattr(subs._dns_resolver, "resolve", fake_resolve)
        resolves, ips = subs.checkDNS("www", "example.com")
        assert resolves is True
        assert ips == ["1.2.3.4"]

    def test_aaaa_fallback_when_no_a_record(self, monkeypatch):
        def fake_resolve(name, rtype, lifetime=None):
            if rtype == "A":
                raise dns.resolver.NoAnswer()
            return ["::1"]

        monkeypatch.setattr(subs._dns_resolver, "resolve", fake_resolve)
        resolves, ips = subs.checkDNS("www", "example.com")
        assert resolves is True
        assert ips == ["::1"]

    def test_nxdomain_short_circuits_aaaa_lookup(self, monkeypatch):
        calls = []

        def fake_resolve(name, rtype, lifetime=None):
            calls.append(rtype)
            raise dns.resolver.NXDOMAIN()

        monkeypatch.setattr(subs._dns_resolver, "resolve", fake_resolve)
        resolves, ips = subs.checkDNS("nope", "example.com")
        assert resolves is False
        assert ips == []
        assert calls == ["A"]

    def test_no_records_of_either_type(self, monkeypatch):
        def fake_resolve(name, rtype, lifetime=None):
            raise dns.resolver.NoAnswer()

        monkeypatch.setattr(subs._dns_resolver, "resolve", fake_resolve)
        resolves, ips = subs.checkDNS("www", "example.com")
        assert resolves is False
        assert ips == []


class TestSaveResults:
    def test_txt(self, tmp_path):
        out = tmp_path / "out.txt"
        results = [{"url": "https://www.example.com", "status_code": 200, "dns_only": False}]
        assert subs.saveResults(results, str(out), "txt") is True
        assert "https://www.example.com (status code: 200)" in out.read_text(encoding="utf-8")

    def test_json(self, tmp_path):
        out = tmp_path / "out.json"
        results = [{"subdomain": "www.example.com", "status_code": 200, "dns_only": False}]
        assert subs.saveResults(results, str(out), "json") is True
        assert json.loads(out.read_text(encoding="utf-8")) == results

    def test_csv(self, tmp_path):
        out = tmp_path / "out.csv"
        results = [{"subdomain": "www.example.com", "status_code": 200}]
        assert subs.saveResults(results, str(out), "csv") is True
        content = out.read_text(encoding="utf-8")
        assert "subdomain" in content
        assert "www.example.com" in content


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class FakeSession:
    """Stand-in for requests.Session with scripted per-scheme responses/exceptions."""

    def __init__(self, responses):
        self.responses = responses  # {scheme: status_code or Exception}
        self.calls = []

    def get(self, url, timeout=None, headers=None, allow_redirects=None):
        scheme = url.split("://")[0]
        self.calls.append(scheme)
        outcome = self.responses.get(scheme)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)


class TestScanSingleSubdomain:
    def test_dns_failure_returns_none(self, monkeypatch):
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (False, []))
        result = subs.scanSingleSubdomain("nope", "example.com", False, 5, {}, [200], False)
        assert result is None

    def test_wildcard_match_is_skipped(self, monkeypatch):
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (True, ["9.9.9.9"]))
        result = subs.scanSingleSubdomain("wild", "example.com", False, 5, {}, [200], False,
                                           wildcard_ips={"9.9.9.9"})
        assert result is None

    def test_dns_only_mode_returns_result_without_http(self, monkeypatch):
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (True, ["1.2.3.4"]))
        result = subs.scanSingleSubdomain("www", "example.com", False, 5, {}, [200], True)
        assert result["subdomain"] == "www.example.com"
        assert result["dns_only"] is True
        assert result["ip_addresses"] == ["1.2.3.4"]

    def test_https_found_skips_http(self, monkeypatch):
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (True, ["1.2.3.4"]))
        fake_session = FakeSession({"https": 200})
        monkeypatch.setattr(subs, "getSession", lambda: fake_session)

        result = subs.scanSingleSubdomain("www", "example.com", False, 5, {}, [200, 301, 302, 403], False)

        assert result["scheme"] == "https"
        assert result["status_code"] == 200
        assert fake_session.calls == ["https"]  # http never attempted

    def test_falls_back_to_http_when_https_unreachable(self, monkeypatch):
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (True, ["1.2.3.4"]))
        fake_session = FakeSession({"https": requests.exceptions.ConnectionError(), "http": 200})
        monkeypatch.setattr(subs, "getSession", lambda: fake_session)

        result = subs.scanSingleSubdomain("www", "example.com", False, 5, {}, [200], False)

        assert result["scheme"] == "http"
        assert result["status_code"] == 200
        assert fake_session.calls == ["https", "http"]

    def test_status_code_not_in_list_returns_none(self, monkeypatch):
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (True, ["1.2.3.4"]))
        fake_session = FakeSession({"https": 404, "http": 404})
        monkeypatch.setattr(subs, "getSession", lambda: fake_session)

        result = subs.scanSingleSubdomain("www", "example.com", False, 5, {}, [200], False)

        assert result is None

    def test_redirect_is_not_followed(self, monkeypatch):
        # allow_redirects must be False so a 301 is reported directly, not the redirect target
        monkeypatch.setattr(subs, "checkDNS", lambda sub, domain, timeout: (True, ["1.2.3.4"]))
        fake_session = FakeSession({"https": 301})
        monkeypatch.setattr(subs, "getSession", lambda: fake_session)

        result = subs.scanSingleSubdomain("mail", "example.com", False, 5, {}, [200, 301, 302, 403], False)

        assert result["status_code"] == 301


class TestScanSubdomains:
    def test_basic_scan_writes_expected_results(self, tmp_path, monkeypatch):
        monkeypatch.setattr(subs, "detectWildcard", lambda domain, timeout: (False, []))

        def fake_scan(sub, domain, verbose, timeout, headers, status_codes, dns_only, wildcard_ips=None):
            if sub == "www":
                return {"subdomain": f"www.{domain}", "scheme": "https", "status_code": 200,
                         "ip_addresses": ["1.2.3.4"], "url": f"https://www.{domain}", "dns_only": False}
            return None

        monkeypatch.setattr(subs, "scanSingleSubdomain", fake_scan)

        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("www\nmail\nftp\n", encoding="utf-8")
        output_file = tmp_path / "out.json"

        results = subs.scanSubdomains("example.com", str(wordlist), threads=2, delay=0,
                                       output_file=str(output_file), output_format="json")

        assert len(results) == 1
        assert results[0]["subdomain"] == "www.example.com"
        assert json.loads(output_file.read_text(encoding="utf-8")) == results

    def test_resume_merges_previous_results_with_new_ones(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subs, "detectWildcard", lambda domain, timeout: (False, []))

        def fake_scan(sub, domain, verbose, timeout, headers, status_codes, dns_only, wildcard_ips=None):
            if sub == "mail":
                return {"subdomain": f"mail.{domain}", "scheme": "https", "status_code": 200,
                         "ip_addresses": ["5.6.7.8"], "url": f"https://mail.{domain}", "dns_only": False}
            return None

        monkeypatch.setattr(subs, "scanSingleSubdomain", fake_scan)

        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("www\nmail\nftp\n", encoding="utf-8")

        progress_file = tmp_path / ".subspy_progress_example_com.json"
        subs.saveProgress(str(progress_file), {"www", "ftp"},
                           [{"subdomain": "www.example.com", "scheme": "https", "status_code": 200,
                             "ip_addresses": ["1.2.3.4"], "url": "https://www.example.com", "dns_only": False}])

        results = subs.scanSubdomains("example.com", str(wordlist), threads=2, delay=0, resume=True)

        subdomains_found = {r["subdomain"] for r in results}
        assert subdomains_found == {"www.example.com", "mail.example.com"}
        assert not progress_file.exists()  # cleaned up after successful completion


class TestProgressRoundTrip:
    def test_round_trip_preserves_scanned_and_results(self, tmp_path):
        progress_file = str(tmp_path / "progress.json")
        scanned = {"www", "mail"}
        results = [{"subdomain": "www.example.com", "status_code": 200}]

        subs.saveProgress(progress_file, scanned, results)
        loaded_scanned, loaded_results = subs.loadProgress(progress_file)

        assert loaded_scanned == scanned
        assert loaded_results == results

    def test_missing_file_returns_empty(self, tmp_path):
        loaded_scanned, loaded_results = subs.loadProgress(str(tmp_path / "missing.json"))
        assert loaded_scanned == set()
        assert loaded_results == []
