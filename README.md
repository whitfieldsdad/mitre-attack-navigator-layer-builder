# Mitre ATT&CK Navigator layer builder

A simple Python library for building, editing, and converting ATT&CK Navigator layers between different formats<sub>1</sub>.

<sub>1. Mitre ATT&CK Navigator layers are generally stored in [JSON format](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md), but can also be stored in an XLSX format provided by Mitre.</sub>

## Features

- Create new layers
- Edit existing layers (e.g., to enable/disable techniques, strip comments, apply colour schemes, etc.)
- Programmatically extract features from existing layers (e.g., selected techniques, enabled techniques, disabled techniques, mappings between tactics and techniques, etc.)
- Convert layers between JSON and XLSX formats
- Build XLSX workbooks containing one or more layers
