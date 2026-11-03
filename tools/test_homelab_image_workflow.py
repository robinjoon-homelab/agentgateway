#!/usr/bin/env python3
"""Checks the security properties of the homelab image workflow without a YAML dependency."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/homelab-image.yml"


def job(text, name):
    match = re.search(rf"(?ms)^  {name}:\n(.*?)(?=^  [a-z-]+:\n|\Z)", text)
    if match is None:
        raise AssertionError(f"job {name} was not found")
    return match.group(1)


class HomelabImageWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.triggers = cls.workflow[cls.workflow.index("on:\n"):cls.workflow.index("permissions:\n")]
        cls.policy = job(cls.workflow, "policy")
        cls.build = job(cls.workflow, "build")
        cls.publish = job(cls.workflow, "publish")

    def test_every_build_input_triggers_pull_requests_and_pushes(self):
        # Dockerfile.headless copies all of tools/, and crates/core/build.rs runs a script from it.
        self.assertIn("COPY tools ./tools", (ROOT / "Dockerfile.headless").read_text())
        for path in (".cargo/**", ".github/actions/setup-rust/**", ".github/workflows/homelab-image.yml",
                     "Cargo.lock", "Cargo.toml", "Dockerfile.headless", "catalog/**", "crates/**",
                     "rust-toolchain.toml", "tools/**"):
            self.assertEqual(self.triggers.count(f"      - {path}\n"), 2, path)

    def test_publishes_only_from_main_of_this_repository(self):
        self.assertIn("github.repository == 'robinjoon-homelab/agentgateway' &&", self.publish)
        self.assertIn("github.ref == 'refs/heads/main' &&", self.publish)
        self.assertIn("(github.event_name == 'push' || github.event_name == 'workflow_dispatch')", self.publish)
        self.assertIn("needs: build", self.publish)
        self.assertEqual(self.triggers.count("branches: [main]"), 2)
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertNotIn("tags:\n    -", self.triggers)

    def test_every_job_is_limited_to_this_repository(self):
        for section in (self.policy, self.build, self.publish):
            self.assertIn("github.repository == 'robinjoon-homelab/agentgateway'", section)

    def test_only_the_publish_job_can_reach_credentials(self):
        self.assertIn("permissions:\n  contents: read\n", self.workflow)
        for section in (self.policy, job(self.workflow, "regression"), self.build):
            self.assertNotIn("id-token", section)
            self.assertNotIn("permissions:", section)
            self.assertNotIn("load-ci-secrets", section)
            self.assertNotIn("REGISTRY_PASSWORD", section)
            self.assertNotIn("docker/login-action", section)
        self.assertIn("id-token: write", self.publish)
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("secrets.", self.workflow)

    def test_publish_job_runs_no_repository_code(self):
        self.assertNotIn("actions/checkout", self.publish)
        self.assertNotIn("tools/", self.publish)

    def test_publish_tools_are_ready_before_credentials_load(self):
        first_credentials = self.publish.index("load-ci-secrets")
        self.assertLess(self.publish.index("skopeo --version"), first_credentials)
        self.assertLess(self.publish.index("docker/setup-buildx-action"), first_credentials)

    def test_credentials_use_the_existing_sms_action(self):
        action = "robinjoon-homelab/Simple-K3S-Herness/.github/actions/load-ci-secrets@v1.0.0"
        self.assertEqual(self.publish.count(action), 2)
        self.assertIn("app: zot", self.publish)
        self.assertIn("app: harness", self.publish)

    def test_builds_natively_on_both_architectures(self):
        self.assertIn("arch: amd64\n            runner: ubuntu-24.04\n", self.build)
        self.assertIn("arch: arm64\n            runner: ubuntu-24.04-arm\n", self.build)
        self.assertIn("file: Dockerfile.headless", self.build)
        self.assertIn("push: false", self.build)

    def test_verifies_before_saving_and_saves_only_outside_pull_requests(self):
        self.assertLess(self.build.index("tools/verify_headless_image.sh"),
                        self.build.index("actions/upload-artifact"))
        save = self.build[self.build.index("- name: Save the verified image"):]
        self.assertIn("if: github.event_name != 'pull_request'", save)
        self.assertIn("type=oci,dest=image.tar", self.build)
        self.assertIn("type=docker,name=agentgateway-verify:", self.build)
        self.assertLess(self.build.index("different layers"), self.build.index("tools/verify_headless_image.sh"))

    def test_regression_tests_gate_the_build(self):
        self.regression = job(self.workflow, "regression")
        self.assertIn("needs: [policy, regression]", self.build)
        self.assertIn("--locked", self.regression)
        for test_filter in ("dynamic_ca", "test_target_", "dynamic_backend_guard_covers",
                            "connect::", "tls::", "dfp::"):
            self.assertIn(test_filter, self.regression)
        self.assertNotIn("id-token", self.regression)

    def test_rust_builds_run_one_job_at_a_time(self):
        self.assertIn('CARGO_BUILD_JOBS: "1"', job(self.workflow, "regression"))
        dockerfile = (ROOT / "Dockerfile.headless").read_text()
        self.assertIn("ARG CARGO_BUILD_JOBS=1\n", dockerfile)
        self.assertIn('CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS"', dockerfile)

    def test_verifies_against_a_pinned_harness_revision(self):
        self.assertRegex(self.workflow, r"HARNESS_CONFIG_REVISION: [0-9a-f]{40}\n")
        self.assertIn("ref: ${{ env.HARNESS_CONFIG_REVISION }}", self.build)
        self.assertNotIn("ref: main", self.build)

    def test_publishes_immutable_tags_and_checks_digests(self):
        self.assertIn("IMAGE_TAG: sha-${{ github.sha }}-run-${{ github.run_id }}-${{ github.run_attempt }}",
                      self.workflow)
        self.assertNotIn("latest", self.workflow)
        self.assertIn("--preserve-digests", self.publish)
        self.assertIn("does not contain exactly the verified images", self.publish)

    def test_releases_through_the_harness_without_editing_gitops_files(self):
        self.assertIn("gh workflow run release-central-egress-image.yml", self.publish)
        self.assertIn("--repo robinjoon-homelab/Simple-K3S-Herness", self.publish)
        self.assertIn("--ref main", self.publish)
        self.assertIn("GH_TOKEN: ${{ env.HARNESS_ACTIONS_TOKEN }}", self.publish)
        self.assertNotIn("git push", self.workflow)
        self.assertNotIn("kubectl", self.workflow)
        self.assertLess(self.publish.index("skopeo copy"), self.publish.index("gh workflow run"))

    def test_publishing_can_run_without_requesting_a_release(self):
        self.assertIn("default: false\n        type: boolean", self.triggers)
        step = self.publish[self.publish.index("- name: Request the central egress release"):]
        self.assertIn(
            "if: inputs.release == true || (github.event_name == 'push' && vars.HOMELAB_RELEASE_ON_PUSH == 'true')",
            step,
        )

    def test_external_actions_are_pinned(self):
        references = re.findall(r"(?m)^\s+(?:- )?uses: ([^\s@]+)@(\S+)", self.workflow)
        self.assertTrue(references)
        for name, reference in references:
            if name.startswith("./"):
                continue
            if name.startswith("robinjoon-homelab/"):
                self.assertRegex(reference, r"^v\d+\.\d+\.\d+$", name)
            else:
                self.assertRegex(reference, r"^[0-9a-f]{40}$", name)

    def test_untrusted_values_do_not_enter_shell_scripts(self):
        blocks = re.findall(r"(?ms)^ +run: \|\n(.*?)(?=^ +- name:|^  [a-z-]+:\n|\Z)", self.workflow)
        self.assertGreater(len(blocks), 5)
        for block in blocks:
            self.assertNotIn("${{", block)
        for line in re.findall(r"(?m)^ +run: (?!\|)(.*)$", self.workflow):
            self.assertNotIn("${{", line)


if __name__ == "__main__":
    unittest.main()
