# OSSF Malicious Packages Connector
# Objective

The connector ingests malicious package JSONs from the repo, creates File Observables, hash-based STIX Indicators, and Based-on Relationships in OpenCTI.  

**Connector type:** External Import connector  
**Source:** GitHub repo `ossf/malicious-packages`  
**Target:** OpenCTI, then optional, export Indicators to your SIEM solution and create a blocking list accordingly.
**Schedule:** Hourly  

# Scope

- Ingests malicious package JSONs from the repo, creates File Observables, hash-based STIX Indicators, and Based-on Relationships in OpenCTI
- Maps the following fields into OpenCTI entities (hash-based Indicators and related File Observables)

# Data Mapping

| **OSV fields** | **OpenCTI fields** |
| --- | --- |
| Package name | Indicator name |
| Summary | Description (Observable and Indicator) |
| Score | 80 (configurable) |
| Hash | Name for Observable, Indicator pattern for Indicator |
| URL | External Reference (within the Indicator) |
|  | TLP:CLEAR |
|  | Main Observable Type: File |
|  |  |
|  |  |

# **Additional Notes**

- Platform creation date = Valid from
- The connector targets only sha256 in this version
- The external reference is included in the Indicator object
- Connector runs every 1 hour
- The connector ingests in “chuncks” of 5000 (essential for first run where it targets over 220K packages)

# **Future Developments**  
  
- When there’s more than 1 hash in a package, modification to support Indicator based on multiple Observables -> **To develop and test**
- Add Main Observable Type (File)
- Support SHA1/MD5 if present
