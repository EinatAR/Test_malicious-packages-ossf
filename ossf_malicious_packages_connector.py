import os
import time
import json
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional

from pycti import OpenCTIConnectorHelper, get_config_variable
import stix2


class OSSFMaliciousPackagesConnector:
    def __init__(self):
        # Load config from environment / yaml
        config = self._load_config()
        self.helper = OpenCTIConnectorHelper(config)

        # Connector-specific config
        self.github_repo_url = get_config_variable(
            "OSSF_GITHUB_REPO_URL", ["ossf", "github_repo_url"], config
        )
        self.github_branch = get_config_variable(
            "OSSF_GITHUB_BRANCH", ["ossf", "branch"], config, default="main"
        )
        self.local_repo_path = get_config_variable(
            "OSSF_LOCAL_REPO_PATH", ["ossf", "local_repo_path"], config,
            default="/opt/ossf-malicous-packages-repo",
        )
        self.run_interval = int(
            get_config_variable(
                "OSSF_RUN_INTERVAL_SECONDS",
                ["ossf", "run_interval_seconds"],
                config,
                default=86400,
            )
        )
        self.default_score = int(
            get_config_variable(
                "OSSF_DEFAULT_SCORE",
                ["ossf", "default_score"],
                config,
                default=80,
            )
        )
        self.source_name = get_config_variable(
            "OSSF_SOURCE_NAME",
            ["ossf", "source_name"],
            config,
            default="ossf/malicious-packages",
        )

        self.logger = self.helper.log_info

    @staticmethod
    def _load_config() -> Dict[str, Any]:
        # Standard way if you use the template loader,
        # or inline YAML load, depending on your deployment.
        import yaml

        config_file_path = os.path.join(os.path.dirname(__file__), "config.yml")
        with open(config_file_path, "r") as f:
            return yaml.safe_load(f)

    # -------------------------------------------------------------------------
    # Git / repo utilities
    # -------------------------------------------------------------------------

    def _init_or_update_repo(self) -> None:
        """Clone or update the local repo."""
        if not os.path.isdir(self.local_repo_path):
            self.helper.log_info(f"Cloning {self.github_repo_url} to {self.local_repo_path}")
            subprocess.check_call(
                ["git", "clone", "--branch", self.github_branch, self.github_repo_url, self.local_repo_path]
            )
        else:
            self.helper.log_info(f"Updating repo in {self.local_repo_path}")
            subprocess.check_call(["git", "-C", self.local_repo_path, "fetch", "origin"])
            subprocess.check_call(["git", "-C", self.local_repo_path, "checkout", self.github_branch])
            subprocess.check_call(["git", "-C", self.local_repo_path, "pull", "origin", self.github_branch])

    def _get_current_head(self) -> str:
        result = subprocess.check_output(
            ["git", "-C", self.local_repo_path, "rev-parse", "HEAD"]
        )
        return result.decode().strip()

    def _get_changed_files(self, old_commit: Optional[str], new_commit: str) -> List[str]:
        """
        Return list of paths to JSON files under osv/malicious/** changed between
        old_commit and new_commit. If old_commit is None, return all.
        """
        if old_commit is None:
            # first run: process all malicious JSONs
            malicious_dir = os.path.join(self.local_repo_path, "osv", "malicious")
            changed_files = []
            for root, _, files in os.walk(malicious_dir):
                for f in files:
                    if f.endswith(".json"):
                        changed_files.append(os.path.join(root, f))
            return changed_files

        diff_cmd = [
            "git",
            "-C",
            self.local_repo_path,
            "diff",
            "--name-only",
            f"{old_commit}..{new_commit}",
            "--",
            "osv/malicious",
        ]
        output = subprocess.check_output(diff_cmd).decode().splitlines()
        # Prepend repo path
        changed_files = [
            os.path.join(self.local_repo_path, p)
            for p in output
            if p.endswith(".json")
        ]
        return changed_files

    def _build_github_blob_url(self, file_path: str, commit: str) -> str:
        """
        Convert local file path to GitHub blob URL for that commit.
        Assumes repo layout: <local_repo_path>/<relative_path>
        and URL: https://github.com/ossf/malicious-packages/blob/<commit>/<relative_path>
        """
        # Normalise and remove local repo prefix
        rel_path = os.path.relpath(file_path, self.local_repo_path).replace("\\", "/")
        return f"{self.github_repo_url.replace('.git', '')}/blob/{commit}/{rel_path}"

    # -------------------------------------------------------------------------
    # OSV parsing → File + Indicator
    # -------------------------------------------------------------------------

    def _parse_osv_json(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            self.helper.log_error(f"Error reading OSV JSON {file_path}: {e}")
            return None

        # We assume standard OSV schema. Important fields:
        osv_id = data.get("id")
        summary = data.get("summary")
        affected = data.get("affected", [])

        if not affected:
            self.helper.log_info(f"No 'affected' section in {file_path}, skipping")
            return None

        # For now, we just take the first affected package
        pkg_info = affected[0].get("package", {})
        ecosystem = pkg_info.get("ecosystem", "unknown")
        name = pkg_info.get("name", "unknown")

        # Hashes may be stored in ecosystem-specific ways.
        # For this first version, we assume they are in a 'database_specific' or
        # 'artifacts' section. Adjust this to match the actual repo format.
        hashes = self._extract_hashes_from_osv(data)
        if not hashes:
            self.helper.log_info(f"No hashes found in {file_path}, skipping")
            return None

        return {
            "osv_id": osv_id,
            "summary": summary,
            "ecosystem": ecosystem,
            "package": name,
            "hashes": hashes,
        }

    def _extract_hashes_from_osv(self, osv_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract hashes from OSV entry.

        Return structure:
          {
            "SHA256": ["hash1", "hash2"],
            "SHA1": ["..."],
            "MD5": ["..."],
          }

        You will need to adapt this function to the actual format used by
        ossf/malicious-packages. For now we look in a few common places.
        """
        hashes: Dict[str, List[str]] = {}

        # Example: some OSV entries might store artifact info under "database_specific"
        db_spec = osv_data.get("database_specific", {})
        artifacts = db_spec.get("artifacts", [])

        for art in artifacts:
            algo = art.get("hash", {}).get("algo")
            value = art.get("hash", {}).get("value")
            if algo and value:
                algo_upper = algo.upper()
                hashes.setdefault(algo_upper, []).append(value)

        # Extend here if hashes are stored differently in the repo

        return hashes

    def _create_file_and_indicator_objects(
        self,
        parsed: Dict[str, Any],
        github_url: str,
    ) -> List[stix2.DomainObject]:
        objects: List[stix2.DomainObject] = []

        ecosystem = parsed["ecosystem"]
        package = parsed["package"]
        summary = parsed.get("summary") or f"Malicious package {ecosystem}/{package}"

        name = f"{ecosystem}/{package}"
        score = self.default_score

        # External reference shared by File & Indicator
        external_ref = stix2.ExternalReference(
            source_name=self.source_name,
            url=github_url,
            external_id=parsed.get("osv_id"),
        )

        # Build File observable with multiple hashes
        file_kwargs = {
            "type": "file",
            "name": name,
            "custom_properties": {
                "x_opencti_description": summary,
                "x_opencti_score": score,
                "external_references": [external_ref],
            },
        }

        # Build the "hashes" dict for STIX2 File
        hashes = {}
        for algo, values in parsed["hashes"].items():
            # If multiple values for same algo, pick first for 'hashes'
            # and keep the rest in the pattern. Or we can keep all if needed.
            if values:
                hashes[algo] = values[0]
        if hashes:
            file_kwargs["hashes"] = hashes

        file_stix = stix2.File(**file_kwargs)
        objects.append(file_stix)

        # Build Indicator pattern:
        patterns = []

        for algo, values in parsed["hashes"].items():
            for v in values:
                # Example: [file:hashes.'SHA256' = 'xxx']
                patterns.append(f"[file:hashes.'{algo}' = '{v}']")

        if not patterns:
            return objects  # no indicator if no hashes

        if len(patterns) == 1:
            pattern = patterns[0]
        else:
            pattern = " OR ".join(patterns)

        indicator = stix2.Indicator(
            name=name,
            description=summary,
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.utcnow().isoformat(timespec="seconds") + "Z",
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_main_observable_type": "File",
                "external_references": [external_ref],
            },
        )
        objects.append(indicator)

        # based-on relationship: Indicator → File
        rel = stix2.Relationship(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=file_stix.id,
        )
        objects.append(rel)

        return objects

    # -------------------------------------------------------------------------
    # Main run loop
    # -------------------------------------------------------------------------

    def _process_once(self) -> None:
        self.helper.log_info("Starting OSSF Malicious Packages run")

        # 1. Ensure repo is up to date
        self._init_or_update_repo()
        current_head = self._get_current_head()

        # 2. Get connector state
        state = self.helper.get_state() or {}
        last_commit = state.get("last_commit")
        self.helper.log_info(f"Last commit in state: {last_commit}, current: {current_head}")

        # 3. Find changed (or all, on first run) JSONs
        changed_files = self._get_changed_files(last_commit, current_head)
        self.helper.log_info(f"Found {len(changed_files)} changed OSV JSON files to process")

        all_objects: List[stix2.DomainObject] = []

        for file_path in changed_files:
            parsed = self._parse_osv_json(file_path)
            if not parsed:
                continue

            github_url = self._build_github_blob_url(file_path, current_head)
            objs = self._create_file_and_indicator_objects(parsed, github_url)
            if not objs:
                continue

            all_objects.extend(objs)

        if not all_objects:
            self.helper.log_info("No new objects to send this run")
        else:
            # 4. Create and send STIX bundle
            bundle = self.helper.stix2_create_bundle(all_objects)
            self.helper.send_stix2_bundle(bundle)
            self.helper.log_info(f"Sent bundle with {len(all_objects)} objects to OpenCTI")

        # 5. Update state
        new_state = {"last_commit": current_head, "last_run": datetime.utcnow().isoformat() + "Z"}
        self.helper.set_state(new_state)
        self.helper.log_info(f"State updated: {new_state}")

    def run(self) -> None:
        self.helper.log_info("Starting OSSF Malicious Packages connector main loop")
        while True:
            try:
                self._process_once()
            except Exception as e:
                self.helper.log_error(f"Error during processing: {e}")

            self.helper.log_info(f"Sleeping for {self.run_interval} seconds")
            time.sleep(self.run_interval)


if __name__ == "__main__":
    try:
        connector = OSSFMaliciousPackagesConnector()
        connector.run()
    except Exception as e:
        logging.exception(e)
        raise
