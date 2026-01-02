import os
import time
import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import yaml
import requests
import stix2
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIApiClient

# TLP:CLEAR marking definition (STIX ID)
TLP_CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

class OSSFMaliciousPackagesConnector:
    def __init__(self):
        # Load config from file + env  
        self.config = self._load_config()   
        self.helper = OpenCTIConnectorHelper(self.config)

        # OpenCTI API client
        self.api_client = OpenCTIApiClient(
            self.config["opencti"]["url"],
            self.config["opencti"]["token"],
        )

        # Connector-specific config
        self.github_repo_url = get_config_variable(
            "OSSF_GITHUB_REPO_URL", ["ossf", "github_repo_url"], self.config
        )
        self.github_branch = get_config_variable(
            "OSSF_GITHUB_BRANCH", ["ossf", "branch"], self.config, default="main"
        )
        self.local_repo_path = get_config_variable(
            "OSSF_LOCAL_REPO_PATH",
            ["ossf", "local_repo_path"],   
            self.config,
        )
self.run_interval = int(
            get_config_variable(
                "OSSF_RUN_INTERVAL", ["ossf", "run_interval"], self.config, default=3600
            )
        )
        self.default_score = int(
            get_config_variable(
                "OSSF_DEFAULT_SCORE",
                ["ossf", "default_score"],
                self.config,
                default=80,
            )
        )
         
    # -------------------------------------------------------------------------
    # Config loading
    # -------------------------------------------------------------------------
    def _load_config(self) -> Dict[str, Any]:
        # Adjust this if your config path is different
        config_file_path = os.environ.get(
            "CONNECTOR_CONFIG", 
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml"),
        )
        with open(config_file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

            
    # -------------------------------------------------------------------------
    # Git repository handling
    # -------------------------------------------------------------------------
    def _init_or_update_repo(self) -> None:
        """Clone or pull the OSSF malicious-packages repo."""
        if not os.path.isdir(self.local_repo_path):
            self.helper.log_info(
                f"Cloning repo {self.github_repo_url} into {self.local_repo_path}"
            )
            subprocess.check_call(
                ["git", "clone", "--branch", self.github_branch, self.github_repo_url, self.local_repo_path]
            )
        else:
            self.helper.log_info(
                f"Updating repo in {self.local_repo_path}"
            )
           subprocess.check_call(
                ["git", "-C", self.local_repo_path, "fetch", "origin", self.github_branch]
            )
            subprocess.check_call(
                ["git", "-C", self.local_repo_path, "checkout", self.github_branch]
            )
            subprocess.check_call(
                ["git", "-C", self.local_repo_path, "pull", "origin", self.github_branch]
            )
             
    def _get_current_head(self) -> str:
        """Return the current HEAD commit hash of the local repo."""
        result = subprocess.check_output(
            ["git", "-C", self.local_repo_path, "rev-parse", "HEAD"]
        )
        return result.decode("utf-8").strip()
             
    def _get_changed_files(
        self, old_commit: Optional[str], new_commit: str
    ) -> List[str]:
        """
        Return list of JSON files under osv/malicious/** that changed
        between old_commit and new_commit. If old_commit is None, return all.
        """  
        # First run: no previous commit -> process all malicious JSONs
        if old_commit is None:
            malicious_dir = os.path.join(self.local_repo_path, "osv", "malicious")
            changed_files: List[str] = []
            for root, _, files in os.walk(malicious_dir):
                for f in files:
                    if f.endswith(".json"):
                        changed_files.append(os.path.join(root, f))
            return changed_files
    
        # Normal run: only files changed between old_commit and new_commit
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
        output = subprocess.check_output(diff_cmd).decode("utf-8").splitlines()
        changed_files: List[str] = []
        for p in output:
            if p.endswith(".json"):
                changed_files.append(os.path.join(self.local_repo_path, p))
        return changed_files
            
    # -------------------------------------------------------------------------
    # OSV parsing and STIX object creation
    # -------------------------------------------------------------------------
    def _parse_osv_json(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.helper.log_error(f"Failed to parse OSV JSON {file_path}: {e}")
            return None 
            
    def _build_github_blob_url(self, file_path: str, commit: str) -> str:  
        """
        Build a GitHub URL to the specific JSON file at a given commit.
        Assumes the repo is on GitHub and github_repo_url is https://github.com/ORG/REPO.git
        """
        repo_http = self.github_repo_url
        if repo_http.endswith(".git"):
            repo_http = repo_http[:-4]
        # File path relative to repo root
        rel_path = os.path.relpath(file_path, self.local_repo_path)
        return f"{repo_http}/blob/{commit}/{rel_path}"
            
    def _create_objects_for_entry(self, osv_data: Dict[str, Any], source_url: str) -> List[Any]:
        """ 
        Turn one OSV JSON entry into STIX 2 objects:
        - File observable (SCO) with SHA-256.
        - Indicator based on that file observable (pattern on SHA-256).
        - Indicator has description and external reference to the source_url.
        """
        objects: List[Any] = []

        osv_id = osv_data.get("id")   
        summary = osv_data.get("summary") or osv_data.get("details") or "Malicious package"
        
        if not osv_id:
            self.helper.log_error("OSV entry has no 'id'; skipping")
            return objects
            
        # Get SHA-256 from database_specific.malicious-packages-origins[0].sha256
        sha256 = None
        db_spec = osv_data.get("database_specific", {})
        origins = db_spec.get("malicious-packages-origins") or db_spec.get("malicious-packages-origins".replace("_", "-"))
        # origins is expected to be a list of dicts with "sha256"
        if isinstance(origins, list) and origins:
            sha256 = origins[0].get("sha256")
        
        if not sha256:
            self.helper.log_error(f"OSV entry {osv_id} has no sha256; skipping")
            return objects
            
        # File observable (SCO) with description
        file_sco = stix2.File(
            name=osv_id,
            hashes={"SHA-256": sha256},
            custom_properties={
                "x_opencti_description": summary,
                "object_marking_refs": [TLP_CLEAR_ID],
            },
        )
        
        # External reference (using source_url)
        ext_ref = stix2.ExternalReference(
            source_name="ossf-malicious-packages",
            url=source_url,
        )
        
        # Indicator based on file hash
        indicator = stix2.Indicator(   
            name=f"Malicious package {osv_id}",
            description=summary,
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            pattern_type="stix",
            external_references=[ext_ref],
            object_marking_refs=[TLP_CLEAR_ID],
            custom_properties={
                "x_opencti_main_observable_type": "File",
                "x_opencti_score": self.default_score,
            },
        )
        
        # Relationship: indicator based on file observable
        relation = stix2.Relationship( 
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=file_sco.id,
            object_marking_refs=[TLP_CLEAR_ID],
        )
            
        objects.extend([file_sco, indicator, relation])
        return objects
                
    # -------------------------------------------------------------------------
    # Main processing logic
    # -------------------------------------------------------------------------
    def _process_once(self) -> None:
        self.helper.log_info("Starting OSSF Malicious Packages run")
            
        # Initiate a new work in OpenCTI for this run
        friendly_name = "OSSF Malicious Packages full run"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )   
        
        # 1. Ensure repository is up-to-date
        self._init_or_update_repo()
        current_head = self._get_current_head()
    
        # 2. Get connector state
        state = self.helper.get_state() or {}
        last_commit = state.get("last_commit")
        self.helper.log_info(
            f"Last commit in state: {last_commit}, current HEAD: {current_head}"
        )
        
        # 3. Determine which JSON files to process
        changed_files = self._get_changed_files(last_commit, current_head)
        self.helper.log_info(
            f"Found {len(changed_files)} OSV JSON files to process this run"
        )
        
        all_objects: List = []
        
        # 4. Parse each changed file and create STIX objects
        for file_path in changed_files:
            parsed = self._parse_osv_json(file_path)
            if not parsed:
                continue
        
            github_url = self._build_github_blob_url(file_path, current_head)
            objs = self._create_objects_for_entry(parsed, github_url)
            if not objs:
                continue
         
            all_objects.extend(objs)
        
        if not all_objects:
            self.helper.log_info("No new objects to send this run")
        else:
            # 5. Bundle and send to OpenCTI via HTTP STIX2 import, in chunks
            CHUNK_SIZE = 5000  # tune if needed (e.g. 5000–10000)
                
            total = len(all_objects)
            self.helper.log_info(
                f"Preparing to send {total} objects in chunks of {CHUNK_SIZE}"
            )
                
            try:
                chunk_index = 0
                for i in range(0, total, CHUNK_SIZE):
                    chunk_index += 1
                    chunk = all_objects[i : i + CHUNK_SIZE]
        
                    bundle_str = self.helper.stix2_create_bundle(chunk)
            
                    self.helper.log_info(
                        f"Sending bundle chunk {chunk_index} "
                        f"({len(chunk)} objects, items {i}-{i + len(chunk) - 1}) "
                        f"to OpenCTI (STIX2)"
                    )
                
                    result = self.api_client.stix2.import_bundle_from_json(
                        bundle_str,
                        True,  # update=True
                    )
                    self.helper.log_info(
                        f"Chunk {chunk_index} import result: {result}"
                    )
            
            except Exception as e:
                self.helper.log_error(f"Bundle import failed: {e}")
                # Mark work as failed
                self.helper.api.work.to_processed(
                    work_id,
                    f"OSSF Malicious Packages run failed: {e}",
                )
                return  # Don't update state if import failed
                        
        # 6. Update connector state
        new_state = {
            "last_commit": current_head,
            "last_run": datetime.now(timezone.utc).isoformat(),
        }   
        self.helper.set_state(new_state)
        self.helper.log_info(f"State updated: {new_state}")

        # 7. Mark work as processed in OpenCTI
        message = (
            f"{self.helper.connect_name} connector successfully run, "
            f"storing last_commit={current_head}"
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)
        
    def run(self) -> None:
        self.helper.log_info(
            "Starting OSSF Malicious Packages connector main loop"
        )
        while True:
            try:
                self._process_once()
            except Exception as e:
                self.helper.log_error(f"Error during processing: {e}")
            self.helper.log_info(
                f"Sleeping for {self.run_interval} seconds before next run"
            )
            time.sleep(self.run_interval)
        
    
if __name__ == "__main__":   
    try:
        connector = OSSFMaliciousPackagesConnector()
        connector.run()
    except Exception as e:
        logging.exception(e)
            
