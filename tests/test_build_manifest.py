"""Tests for .github/manifests/build_manifest.py"""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# Add the module path so we can import build_manifest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / ".github" / "manifests"))

import build_manifest

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def query_md_content():
    """A well-formed query markdown file."""
    return (
        "# Suspicious Sign-In Activity\n"
        "\n"
        "**Tables:** SigninLogs, AADNonInteractiveUserSignInLogs\n"
        "**Keywords:** brute force, password spray\n"
        "**MITRE:** T1110.001, T1110.003\n"
        "**Domains:** identity, incidents\n"
        "**Platform:** Azure AD\n"
        "**Timeframe:** 7d\n"
        "\n"
        "## Query\n"
        "```kql\n"
        "SigninLogs | where ResultType != 0\n"
        "```\n"
    )


@pytest.fixture
def skill_md_content():
    """A well-formed skill SKILL.md file with YAML frontmatter."""
    return (
        "---\n"
        "name: identity-investigation\n"
        "threat_pulse_domains: identity, incidents\n"
        "drill_down_prompt: Investigate this identity compromise\n"
        "---\n"
        "\n"
        "# Identity Investigation Skill\n"
        "Details here.\n"
    )


@pytest.fixture
def fake_repo(tmp_path):
    """Create a fake repo structure under tmp_path with queries and skills dirs."""
    queries_dir = tmp_path / "queries"
    queries_dir.mkdir()
    skills_dir = tmp_path / ".github" / "skills"
    skills_dir.mkdir(parents=True)
    manifests_dir = tmp_path / ".github" / "manifests"
    manifests_dir.mkdir(parents=True)
    return tmp_path


# ── parse_query_file ────────────────────────────────────────────────────────


class TestParseQueryFile:
    def test_valid_query_file(self, tmp_path, query_md_content):
        md_file = tmp_path / "test_query.md"
        md_file.write_text(query_md_content)

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert result is not None
        assert result["title"] == "Suspicious Sign-In Activity"
        assert result["path"] == "test_query.md"
        assert result["tables"] == ["SigninLogs", "AADNonInteractiveUserSignInLogs"]
        assert result["keywords"] == ["brute force", "password spray"]
        assert result["mitre"] == ["T1110.001", "T1110.003"]
        assert result["domains"] == ["identity", "incidents"]
        assert result["platform"] == ["Azure AD"]
        assert result["timeframe"] == ["7d"]

    def test_missing_title_returns_none(self, tmp_path):
        md_file = tmp_path / "no_title.md"
        md_file.write_text("No heading here\nJust text.\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert result is None

    def test_empty_file_returns_none(self, tmp_path):
        md_file = tmp_path / "empty.md"
        md_file.write_text("")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert result is None

    def test_title_only_no_fields(self, tmp_path):
        md_file = tmp_path / "title_only.md"
        md_file.write_text("# Just a Title\n\nSome body text.\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert result is not None
        assert result["title"] == "Just a Title"
        assert "tables" not in result
        assert "domains" not in result

    def test_unreadable_file_returns_none(self, tmp_path):
        bad_path = tmp_path / "nonexistent.md"

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(bad_path)

        assert result is None

    def test_title_found_within_first_five_lines(self, tmp_path):
        md_file = tmp_path / "late_title.md"
        md_file.write_text("\n\n\n# Late Title\n\n**Domains:** endpoint\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert result is not None
        assert result["title"] == "Late Title"

    def test_title_after_line_five_returns_none(self, tmp_path):
        md_file = tmp_path / "too_late.md"
        lines = ["line\n"] * 6 + ["# Too Late Title\n"]
        md_file.write_text("".join(lines))

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert result is None

    def test_path_uses_forward_slashes(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        md_file = sub / "query.md"
        md_file.write_text("# Test\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_query_file(md_file)

        assert "\\" not in result["path"]
        assert result["path"] == "sub/query.md"


# ── parse_skill_file ───────────────────────────────────────────────────────


class TestParseSkillFile:
    def test_valid_skill_file(self, tmp_path, skill_md_content):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(skill_md_content)

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result is not None
        assert result["name"] == "identity-investigation"
        assert result["domains"] == ["identity", "incidents"]
        assert result["prompt"] == "Investigate this identity compromise"

    def test_no_frontmatter_returns_none(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("# No Frontmatter\nJust text.\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result is None

    def test_unclosed_frontmatter_returns_none(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("---\nname: broken\nno closing delimiter\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result is None

    def test_invalid_yaml_returns_none(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("---\n: : : broken yaml [[\n---\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        # May return None due to parse error or invalid structure
        assert result is None

    def test_missing_name_returns_none(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("---\ndescription: no name field\n---\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result is None

    def test_frontmatter_not_dict_returns_none(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("---\n- just\n- a\n- list\n---\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result is None

    def test_domains_as_list(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(
            "---\n"
            "name: test-skill\n"
            "threat_pulse_domains:\n"
            "  - endpoint\n"
            "  - cloud\n"
            "---\n"
        )

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result["domains"] == ["endpoint", "cloud"]

    def test_no_domains_or_prompt(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("---\nname: minimal-skill\n---\n")

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(skill_file)

        assert result is not None
        assert result["name"] == "minimal-skill"
        assert "domains" not in result
        assert "prompt" not in result

    def test_unreadable_skill_returns_none(self, tmp_path):
        bad_path = tmp_path / "nonexistent_SKILL.md"

        with patch.object(build_manifest, "REPO_ROOT", tmp_path):
            result = build_manifest.parse_skill_file(bad_path)

        assert result is None


# ── scan_queries / scan_skills ─────────────────────────────────────────────


class TestScanners:
    def test_scan_queries_finds_files(self, fake_repo, query_md_content):
        queries_dir = fake_repo / "queries"
        (queries_dir / "q1.md").write_text(query_md_content)
        sub = queries_dir / "sub"
        sub.mkdir()
        (sub / "q2.md").write_text("# Another Query\n\n**Domains:** endpoint\n")

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "QUERIES_DIR", fake_repo / "queries"):
            results = build_manifest.scan_queries()

        assert len(results) == 2
        titles = {r["title"] for r in results}
        assert "Suspicious Sign-In Activity" in titles
        assert "Another Query" in titles

    def test_scan_queries_missing_dir(self, tmp_path):
        with patch.object(build_manifest, "QUERIES_DIR", tmp_path / "nonexistent"):
            results = build_manifest.scan_queries()

        assert results == []

    def test_scan_skills_finds_files(self, fake_repo, skill_md_content):
        skill_dir = fake_repo / ".github" / "skills" / "my-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(skill_md_content)

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "SKILLS_DIR", fake_repo / ".github" / "skills"):
            results = build_manifest.scan_skills()

        assert len(results) == 1
        assert results[0]["name"] == "identity-investigation"

    def test_scan_skills_missing_dir(self, tmp_path):
        with patch.object(build_manifest, "SKILLS_DIR", tmp_path / "nonexistent"):
            results = build_manifest.scan_skills()

        assert results == []

    def test_scan_queries_skips_unparseable(self, fake_repo):
        queries_dir = fake_repo / "queries"
        (queries_dir / "good.md").write_text("# Good Query\n**Domains:** identity\n")
        (queries_dir / "bad.md").write_text("no title here\n")

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "QUERIES_DIR", fake_repo / "queries"):
            results = build_manifest.scan_queries()

        assert len(results) == 1
        assert results[0]["title"] == "Good Query"


# ── validate ───────────────────────────────────────────────────────────────


class TestValidate:
    def test_valid_query_no_warnings(self):
        queries = [{
            "path": "queries/test.md",
            "title": "Test",
            "domains": ["identity"],
            "tables": ["SigninLogs"],
            "keywords": ["brute force"],
            "mitre": ["T1110"],
        }]
        skills = [{
            "path": ".github/skills/test/SKILL.md",
            "name": "test-skill",
            "domains": ["identity"],
            "prompt": "Investigate",
        }]

        # Suppress coverage warnings by providing all domains
        all_domain_queries = []
        all_domain_skills = []
        for d in build_manifest.VALID_DOMAINS:
            all_domain_queries.append({
                "path": f"queries/{d}.md",
                "title": d,
                "domains": [d],
                "tables": ["T"],
                "keywords": ["K"],
                "mitre": ["M"],
            })
            all_domain_skills.append({
                "path": f".github/skills/{d}/SKILL.md",
                "name": f"{d}-skill",
                "domains": [d],
                "prompt": "P",
            })

        warnings = build_manifest.validate(all_domain_queries, all_domain_skills)
        assert len(warnings) == 0

    def test_missing_domains_warning(self):
        queries = [{
            "path": "queries/test.md",
            "title": "Test",
            "tables": ["T"],
            "keywords": ["K"],
            "mitre": ["M"],
        }]
        warnings = build_manifest.validate(queries, [])
        assert any("missing Domains" in w for w in warnings)

    def test_unknown_domain_warning(self):
        queries = [{
            "path": "queries/test.md",
            "title": "Test",
            "domains": ["fake_domain"],
            "tables": ["T"],
            "keywords": ["K"],
            "mitre": ["M"],
        }]
        warnings = build_manifest.validate(queries, [])
        assert any("unknown domain 'fake_domain'" in w for w in warnings)

    def test_missing_tables_keywords_mitre(self):
        queries = [{
            "path": "queries/test.md",
            "title": "Test",
            "domains": ["identity"],
        }]
        warnings = build_manifest.validate(queries, [])
        table_warnings = [w for w in warnings if "missing Tables" in w]
        keyword_warnings = [w for w in warnings if "missing Keywords" in w]
        mitre_warnings = [w for w in warnings if "missing MITRE" in w]
        assert len(table_warnings) == 1
        assert len(keyword_warnings) == 1
        assert len(mitre_warnings) == 1

    def test_skill_missing_domains_warning(self):
        skills = [{
            "path": ".github/skills/test/SKILL.md",
            "name": "custom-investigation",
            "prompt": "P",
        }]
        warnings = build_manifest.validate([], skills)
        assert any("missing threat_pulse_domains" in w for w in warnings)

    def test_skill_missing_prompt_warning(self):
        skills = [{
            "path": ".github/skills/test/SKILL.md",
            "name": "custom-investigation",
            "domains": ["identity"],
        }]
        warnings = build_manifest.validate([], skills)
        assert any("missing drill_down_prompt" in w for w in warnings)

    def test_excluded_skills_not_validated(self):
        """Skills like detection-authoring should be excluded from domain/prompt validation."""
        skills = [{
            "path": ".github/skills/det/SKILL.md",
            "name": "detection-authoring",
            # No domains or prompt, but should NOT generate warnings
        }]
        warnings = build_manifest.validate([], skills)
        skill_warnings = [w for w in warnings if "SKILL" in w]
        assert len(skill_warnings) == 0

    def test_coverage_warnings_for_missing_domains(self):
        warnings = build_manifest.validate([], [])
        coverage_warnings = [w for w in warnings if w.startswith("COVERAGE")]
        # Should have warnings for each valid domain (query + skill)
        assert len(coverage_warnings) == 2 * len(build_manifest.VALID_DOMAINS)

    def test_empty_domains_list_treated_as_missing(self):
        queries = [{
            "path": "queries/test.md",
            "title": "Test",
            "domains": [],
            "tables": ["T"],
            "keywords": ["K"],
            "mitre": ["M"],
        }]
        warnings = build_manifest.validate(queries, [])
        assert any("missing Domains" in w for w in warnings)

    def test_skill_unknown_domain_warning(self):
        skills = [{
            "path": ".github/skills/test/SKILL.md",
            "name": "custom-investigation",
            "domains": ["bogus"],
            "prompt": "P",
        }]
        warnings = build_manifest.validate([], skills)
        assert any("unknown domain 'bogus'" in w for w in warnings)


# ── build_manifest / build_slim_manifest ───────────────────────────────────


class TestBuildManifest:
    def test_build_manifest_structure(self):
        queries = [{"title": "Q1", "path": "queries/q1.md", "domains": ["identity"],
                     "tables": ["T"], "keywords": ["K"], "mitre": ["M"]}]
        skills = [{"name": "S1", "path": ".github/skills/s1/SKILL.md",
                    "domains": ["identity"], "prompt": "P"}]

        result = build_manifest.build_manifest(queries, skills)

        assert "generated" in result
        assert "valid_domains" in result
        assert result["queries"] == queries
        assert result["skills"] == skills
        assert result["valid_domains"] == sorted(build_manifest.VALID_DOMAINS)

    def test_build_slim_manifest_strips_extra_fields(self):
        queries = [{"title": "Q1", "path": "queries/q1.md", "domains": ["identity"],
                     "tables": ["SigninLogs"], "keywords": ["spray"], "mitre": ["T1110"],
                     "platform": ["Azure AD"], "timeframe": ["7d"]}]
        skills = [{"name": "S1", "path": ".github/skills/s1/SKILL.md",
                    "domains": ["identity"], "prompt": "P"}]

        result = build_manifest.build_slim_manifest(queries, skills)

        slim_q = result["queries"][0]
        assert "title" in slim_q
        assert "path" in slim_q
        assert "domains" in slim_q
        assert "mitre" in slim_q
        assert "tables" not in slim_q
        assert "keywords" not in slim_q
        assert "platform" not in slim_q
        assert "timeframe" not in slim_q

        slim_s = result["skills"][0]
        assert "name" in slim_s
        assert "path" in slim_s
        assert "domains" in slim_s
        assert "prompt" in slim_s

    def test_slim_manifest_omits_missing_optional_fields(self):
        queries = [{"title": "Q1", "path": "queries/q1.md"}]
        skills = [{"name": "S1", "path": ".github/skills/s1/SKILL.md"}]

        result = build_manifest.build_slim_manifest(queries, skills)

        slim_q = result["queries"][0]
        assert "domains" not in slim_q
        assert "mitre" not in slim_q

        slim_s = result["skills"][0]
        assert "domains" not in slim_s
        assert "prompt" not in slim_s

    def test_generated_timestamp_is_utc(self):
        result = build_manifest.build_manifest([], [])
        ts = result["generated"]
        assert ts.endswith("Z")
        # Should be parseable
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        assert dt is not None


# ── _write_yaml / write_manifest / write_full_manifest ─────────────────────


class TestWriteManifest:
    def test_write_yaml_creates_file(self, tmp_path):
        output = tmp_path / "out" / "test.yaml"
        data = {"key": "value", "items": [1, 2, 3]}

        build_manifest._write_yaml(output, data, "# header\n")

        assert output.exists()
        content = output.read_text()
        assert content.startswith("# header\n")
        parsed = yaml.safe_load(content)
        assert parsed["key"] == "value"
        assert parsed["items"] == [1, 2, 3]

    def test_write_yaml_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "deep" / "nested" / "dir" / "manifest.yaml"

        build_manifest._write_yaml(output, {"a": 1}, "# h\n")

        assert output.exists()

    def test_write_manifest_writes_slim(self, tmp_path):
        manifest_path = tmp_path / "manifest.yaml"
        slim = {"generated": "2026-01-01T00:00:00Z", "valid_domains": [], "queries": [], "skills": []}

        with patch.object(build_manifest, "MANIFEST_PATH", manifest_path):
            build_manifest.write_manifest(slim)

        assert manifest_path.exists()
        content = manifest_path.read_text()
        assert "Slim version" in content
        assert "DO NOT EDIT MANUALLY" in content

    def test_write_full_manifest(self, tmp_path):
        manifest_path = tmp_path / "full.yaml"
        full = {"generated": "2026-01-01T00:00:00Z", "valid_domains": [], "queries": [], "skills": []}

        with patch.object(build_manifest, "MANIFEST_FULL_PATH", manifest_path):
            build_manifest.write_full_manifest(full)

        assert manifest_path.exists()
        content = manifest_path.read_text()
        assert "Full" in content


# ── main ───────────────────────────────────────────────────────────────────


class TestMain:
    def test_main_validate_only(self, fake_repo, query_md_content, skill_md_content):
        queries_dir = fake_repo / "queries"
        (queries_dir / "q1.md").write_text(query_md_content)
        skill_dir = fake_repo / ".github" / "skills" / "test"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(skill_md_content)

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "QUERIES_DIR", fake_repo / "queries"), \
             patch.object(build_manifest, "SKILLS_DIR", fake_repo / ".github" / "skills"), \
             patch("sys.argv", ["build_manifest.py", "--validate-only"]):
            result = build_manifest.main()

        # Should not write any files
        manifest_path = fake_repo / ".github" / "manifests" / "discovery-manifest.yaml"
        assert not manifest_path.exists()

    def test_main_generates_slim_manifest(self, fake_repo, query_md_content, skill_md_content):
        queries_dir = fake_repo / "queries"
        (queries_dir / "q1.md").write_text(query_md_content)
        skill_dir = fake_repo / ".github" / "skills" / "test"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(skill_md_content)

        manifest_path = fake_repo / ".github" / "manifests" / "discovery-manifest.yaml"

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "QUERIES_DIR", fake_repo / "queries"), \
             patch.object(build_manifest, "SKILLS_DIR", fake_repo / ".github" / "skills"), \
             patch.object(build_manifest, "MANIFEST_PATH", manifest_path), \
             patch.object(build_manifest, "MANIFESTS_DIR", fake_repo / ".github" / "manifests"), \
             patch("sys.argv", ["build_manifest.py"]):
            build_manifest.main()

        assert manifest_path.exists()

    def test_main_full_flag_generates_both(self, fake_repo, query_md_content, skill_md_content):
        queries_dir = fake_repo / "queries"
        (queries_dir / "q1.md").write_text(query_md_content)
        skill_dir = fake_repo / ".github" / "skills" / "test"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(skill_md_content)

        slim_path = fake_repo / ".github" / "manifests" / "discovery-manifest.yaml"
        full_path = fake_repo / ".github" / "manifests" / "discovery-manifest-full.yaml"

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "QUERIES_DIR", fake_repo / "queries"), \
             patch.object(build_manifest, "SKILLS_DIR", fake_repo / ".github" / "skills"), \
             patch.object(build_manifest, "MANIFEST_PATH", slim_path), \
             patch.object(build_manifest, "MANIFEST_FULL_PATH", full_path), \
             patch.object(build_manifest, "MANIFESTS_DIR", fake_repo / ".github" / "manifests"), \
             patch("sys.argv", ["build_manifest.py", "--full"]):
            build_manifest.main()

        assert slim_path.exists()
        assert full_path.exists()

    def test_main_returns_1_on_error_warnings(self, fake_repo):
        """Queries missing required fields should cause exit code 1."""
        queries_dir = fake_repo / "queries"
        # Query with title but missing all metadata fields
        (queries_dir / "bad.md").write_text("# Bad Query\n\nNo metadata.\n")

        manifest_path = fake_repo / ".github" / "manifests" / "discovery-manifest.yaml"

        with patch.object(build_manifest, "REPO_ROOT", fake_repo), \
             patch.object(build_manifest, "QUERIES_DIR", fake_repo / "queries"), \
             patch.object(build_manifest, "SKILLS_DIR", fake_repo / ".github" / "skills"), \
             patch.object(build_manifest, "MANIFEST_PATH", manifest_path), \
             patch.object(build_manifest, "MANIFESTS_DIR", fake_repo / ".github" / "manifests"), \
             patch("sys.argv", ["build_manifest.py"]):
            result = build_manifest.main()

        assert result == 1

    def test_main_returns_0_when_only_coverage_warnings(self):
        """Coverage warnings alone should not cause a non-zero exit."""
        # Empty queries and skills means only COVERAGE warnings
        with patch.object(build_manifest, "QUERIES_DIR", Path("/nonexistent")), \
             patch.object(build_manifest, "SKILLS_DIR", Path("/nonexistent")), \
             patch("sys.argv", ["build_manifest.py", "--validate-only"]):
            result = build_manifest.main()

        assert result == 0


# ── VALID_DOMAINS constant ─────────────────────────────────────────────────


class TestConstants:
    def test_valid_domains_is_set(self):
        assert isinstance(build_manifest.VALID_DOMAINS, set)
        assert len(build_manifest.VALID_DOMAINS) > 0

    def test_expected_domains_present(self):
        expected = {"incidents", "identity", "endpoint", "email", "cloud"}
        assert expected.issubset(build_manifest.VALID_DOMAINS)
