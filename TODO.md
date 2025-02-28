# TODO

- [ ] Generate example matrices:
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by tactic
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by groups
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by intrusion sets
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by malware clusters
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by tools
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by data sources
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by data components
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by CAPEC techniques
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by courses of action
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by NIST CSF function
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by NIST SP 800-53 controls
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by NIST SP 800-53 sub-controls
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by CVE
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by CVE by CVSS vector (i.e., by vector string, and by expanded vector component)
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by weakness (CWE)
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by attack pattern (CAPEC)
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by location
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by group location
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by intrusion set location
    - [ ] (ATT&CK techniques / ATT&CK tactics) * ATT&CK techniques by campaign location

- [ ] Identify CAPEC equivalent of ATT&CK Navigator layer views
- [ ] Generate ATT&CK Navigator layers based on arbitrary dimensions (e.g., tactics x courses of action, tactics x NIST SP 800-53 controls, etc.)
- [ ] Generate ATT&CK Navigator layers based on arbitrary dimensions and known transformations to those dimensions (e.g., to go from ATT&CK tactic x ATT&CK technique to NIST SP 800-53 control x NIST SP 800-53 sub-control with a heatmap showing the number of techniques in the adjacent dimension - i.e., techniques).

- [ ] Write tool for generically combining ATT&CK Navigator layers, matrices (e.g., NIST SP 800-53 controls by NIST SP 800-53 sub-controls, CVEs by CWEs, CVEs by ATT&CK tactics, CVEs by ATT&CK techniques, etc.)
- [ ] Generate a table containing TTPs used by Muddywater and Oilrig
  - [ ] STIX 2 filters over STIX 2 content
  - [ ] Cypher query over STIX 2 content
  - [ ] SQL query over Parquet files (e.g., via DuckDB, Presto, Trino, etc.)
  - [ ] SQL query against a database (e.g., via DuckDB, Presto, Trino, Pinot, etc.)
  - [ ] Python (i.e., Polars, Pandas)
- [ ] Generate a heatmap comparing TTPs used by Muddywater and Oilrig
    - [ ] Export to ATT&CK Navigator
    - [ ] Export to XLSX
    - [ ] Export to CSV
    - [ ] Export to Parquet
