import os

def initialize(): 
    global BASE_PATH
    global PRINT_RESULTS
    global MACHINE_ID_SHORT
    global EXCEL_AUTOS2_INFORMATION_BASE_PATH
    global TAB_ICS_ATTACK_INTEL_TAL_MAPPING
    global TAB_MITIGATION_IEC_62443_MAPPING
    global TAB_CVE_ICS_MAPPING
    global EXCEL_ICS_ATTACK_MITIGATIONS_PATH
    global TAB_TECHNIQUES_ADDRESSED
    global EXAMPLE_CVES_PATH
    global CVE_API_URL
    global ATTEST_FILE_NAME

    global error_list


    BASE_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "../"))

    # Switch on (True) or of (False) whether the state of the process should be printed
    PRINT_RESULTS = True
    MACHINE_ID_SHORT = "CPS"

    EXCEL_AUTOS2_INFORMATION_BASE_PATH = BASE_PATH + "/knowledge/autos2-knowledge_2023_04_06.xlsx"
    TAB_ICS_ATTACK_INTEL_TAL_MAPPING = "ICS_ATT&CK-Intel_TAL-Mapping"
    TAB_MITIGATION_IEC_62443_MAPPING = "Mitigations-IEC_62443-Mapping"
    TAB_CVE_ICS_MAPPING = "CVE-ICS_ATT&CK-Mapping"

    EXCEL_ICS_ATTACK_MITIGATIONS_PATH = BASE_PATH + "/knowledge/ics-attack-v13.1-mitigations.xlsx"
    TAB_TECHNIQUES_ADDRESSED = "techniques addressed"

    # As the number of requests for the NIST NVD is limited in a certain time, the CVEs that are relevant for the test scenarios are manually stored here
    EXAMPLE_CVES_PATH = BASE_PATH + "/knowledge/example_cves.json"
    CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

    ATTEST_FILE_NAME = "Attest.pdf"

    error_list = []