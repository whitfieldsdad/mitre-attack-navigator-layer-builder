import itertools

JSON_INDENT = 4

MITRE_ATTACK_ENTERPRISE = 'enterprise-attack'
MITRE_ATTACK_MOBILE = 'mobile-attack'
MITRE_ATTACK_ICS = 'ics-attack'

MITRE_ATTACK_ENTERPRISE_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json'
MITRE_ATTACK_MOBILE_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json'
MITRE_ATTACK_ICS_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json'

MITRE_ATTACK_TACTICS = [
  {
    "name": "Credential Access",
    "x_mitre_shortname": "credential-access",
    "external_id": "TA0006"
  },
  {
    "name": "Execution",
    "x_mitre_shortname": "execution",
    "external_id": "TA0002"
  },
  {
    "name": "Impact",
    "x_mitre_shortname": "impact",
    "external_id": "TA0040"
  },
  {
    "name": "Persistence",
    "x_mitre_shortname": "persistence",
    "external_id": "TA0003"
  },
  {
    "name": "Privilege Escalation",
    "x_mitre_shortname": "privilege-escalation",
    "external_id": "TA0004"
  },
  {
    "name": "Lateral Movement",
    "x_mitre_shortname": "lateral-movement",
    "external_id": "TA0008"
  },
  {
    "name": "Defense Evasion",
    "x_mitre_shortname": "defense-evasion",
    "external_id": "TA0005"
  },
  {
    "name": "Exfiltration",
    "x_mitre_shortname": "exfiltration",
    "external_id": "TA0010"
  },
  {
    "name": "Discovery",
    "x_mitre_shortname": "discovery",
    "external_id": "TA0007"
  },
{
    "name": "Collection",
    "x_mitre_shortname": "collection",
    "external_id": "TA0009"
  },
  {
    "name": "Resource Development",
    "x_mitre_shortname": "resource-development",
    "external_id": "TA0042"
  },
  {
    "name": "Reconnaissance",
    "x_mitre_shortname": "reconnaissance",
    "external_id": "TA0043"
  },
  {
    "name": "Command and Control",
    "x_mitre_shortname": "command-and-control",
    "external_id": "TA0011"
  },
  {
    "name": "Initial Access",
    "x_mitre_shortname": "initial-access",
    "external_id": "TA0001"
  }
]

MITRE_ATTACK_TACTIC_SHORTNAMES_TO_NAMES = {
    t['x_mitre_shortname']: t['name'] for t in MITRE_ATTACK_TACTICS
}
MITRE_ATTACK_TACTIC_SHORTNAMES_TO_EXTERNAL_IDS = {
    t['x_mitre_shortname']: t['external_id'] for t in MITRE_ATTACK_TACTICS
}

STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN = {
    MITRE_ATTACK_ENTERPRISE: MITRE_ATTACK_ENTERPRISE_URL,
    MITRE_ATTACK_MOBILE: MITRE_ATTACK_MOBILE_URL,
    MITRE_ATTACK_ICS: MITRE_ATTACK_ICS_URL,
}

# Other data sources
NIST_SP_800_53_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/refs/heads/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json'
NIST_SP_800_53_TO_MITRE_ATTACK_ENTERPRISE_MAPPINGS_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/refs/heads/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-mappings.json'

MITRE_CAPEC_URL = 'https://raw.githubusercontent.com/mitre/cti/refs/heads/master/capec/2.1/stix-capec.json'

# Options for sorting techniques within layers
SORT_ASCENDING_BY_TECHNIQUE_NAME = 0
SORT_DESCENDING_BY_TECHNIQUE_NAME = 1
SORT_ASCENDING_BY_TECHNIQUE_SCORE = 2
SORT_DESCENDING_BY_TECHNIQUE_SCORE = 3

SORT_OPTIONS = [
    SORT_ASCENDING_BY_TECHNIQUE_NAME,
    SORT_DESCENDING_BY_TECHNIQUE_NAME,
    SORT_ASCENDING_BY_TECHNIQUE_SCORE,
    SORT_DESCENDING_BY_TECHNIQUE_SCORE,
]

# Platforms
PRE = 'PRE'
WINDOWS = 'Windows'
LINUX = 'Linux'
MACOS = 'macOS'
NETWORK = 'Network'
AWS = 'AWS'
GCP = 'GCP'
AZURE = 'Azure'
AZURE_AD = 'Azure AD'
OFFICE_365 = 'Office 365'
SAAS = 'SaaS'

ANDROID = 'Android'
IOS = 'iOS'

CONTROL_SERVER = 'Control Server'
DATA_HISTORIAN = 'Data Historian'
ENGINEERING_WORKSTATION = 'Engineering Workstation'
FIELD_CONTROLLER = 'Field Controller/RTU/PLC/IED'
HMI = 'Human Machine Interface'
INPUT_OUTPUT_SERVER = 'Input/Output Server'
SAFETY_INSTRUMENTED_SYSTEM_PROTECTION_RELAY = 'Safety Instrumented System/Protection Relay'

PLATFORMS_BY_DOMAIN = {
    MITRE_ATTACK_ENTERPRISE: [PRE, WINDOWS, LINUX, MACOS, NETWORK, AWS, GCP, AZURE, AZURE_AD, OFFICE_365, SAAS],
    MITRE_ATTACK_MOBILE: [ANDROID, IOS],
    MITRE_ATTACK_ICS: [WINDOWS, CONTROL_SERVER, DATA_HISTORIAN, ENGINEERING_WORKSTATION, FIELD_CONTROLLER, HMI, INPUT_OUTPUT_SERVER, SAFETY_INSTRUMENTED_SYSTEM_PROTECTION_RELAY],
}

PLATFORMS = sorted(set(itertools.chain.from_iterable(PLATFORMS_BY_DOMAIN.values())))

# Default versions
ATTACK_NAVIGATOR_VERSION = '4.9.0'
ATTACK_NAVIGATOR_LAYER_VERSION = '4.5'

# Layout types
SIDE = 'side'
FLAT = 'flat'
MINI = 'mini'

LAYOUT_TYPES = [SIDE, FLAT, MINI]

# Aggregate functions
AVG = 'average'
MIN = 'min'
MAX = 'max'
SUM = 'sum'

LAYOUT_AGGREGATE_FUNCTIONS = [AVG, MIN, MAX, SUM]

NONE = 'none'
ALL = 'all'
ANNOTATED = 'annotated'

# Strategies for merging layers
UNION = 'union'
INTERSECTION = 'intersection'
LEFT_DIFF = 'left_diff'
RIGHT_DIFF = 'right_diff'
SYMMETRIC_DIFF = 'symmetric_diff'
HEATMAP = 'heatmap'

MERGE_STRATEGIES = [
    UNION,
    INTERSECTION,
    LEFT_DIFF,
    RIGHT_DIFF,
    SYMMETRIC_DIFF,
    HEATMAP,
]

DEFAULT_COLOR = 'cornflowerblue'
