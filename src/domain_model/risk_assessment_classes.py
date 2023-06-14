from enum import Enum
import requests
import time
import json
import setup


class Complexity_Enum(Enum):
    UNKNOWN = "UNKNOWN"
    LOW     = "LOW", "PARTIAL"
    HIGH    = "HIGH", "COMPLETE"
    
    def get_min(complexity_1, complexity_2):
        complexity_1:Complexity_Enum
        complexity_2:Complexity_Enum
        complexities = [complexity_1, complexity_2]
        if Complexity_Enum.LOW    in complexities: return Complexity_Enum.LOW
        elif Complexity_Enum.HIGH in complexities: return Complexity_Enum.HIGH
        else: raise ValueError("Unknown Complexity in", complexities)

    def get_max(complexity_1, complexity_2):
        complexity_1:Complexity_Enum
        complexity_2:Complexity_Enum
        complexities = [complexity_1, complexity_2]
        if Complexity_Enum.HIGH  in complexities: return Complexity_Enum.HIGH
        elif Complexity_Enum.LOW in complexities: return Complexity_Enum.LOW
        else: raise ValueError("Unknown Complexity in", complexities)


class Impact_Enum(Enum):
    UNKNOWN = "UNKNOWN"
    NONE    = "NONE"
    LOW     = "LOW", "PARTIAL"
    HIGH    = "HIGH", "COMPLETE"

    def get_max(impact_1, impact_2):
        impact_1:Impact_Enum
        impact_2:Impact_Enum
        impacts = [impact_1, impact_2]
        if Impact_Enum.HIGH   in impacts: return Impact_Enum.HIGH
        elif Impact_Enum.LOW  in impacts: return Impact_Enum.LOW
        elif Impact_Enum.NONE in impacts: return Impact_Enum.NONE
        else: raise ValueError("Unknown Impact in", impacts)


class Risk_Enum(Enum):
    UNDEFINED   = "UNDEFINED"
    NORISK      = "NO RISK"
    VERYLOW     = "VERY LOW"
    LOW         = "LOW"
    MEDIUM      = "MEDIUM"
    HIGH        = "HIGH" 
    VERYHIGH    = "VERY HIGH"

    def get_max(risk_1, risk_2):
        risk_1:Risk_Enum
        risk_2:Risk_Enum
        risks = [risk_1, risk_2]
        if Risk_Enum.VERYHIGH  in risks: return Risk_Enum.VERYHIGH
        elif Risk_Enum.HIGH    in risks: return Risk_Enum.HIGH
        elif Risk_Enum.MEDIUM  in risks: return Risk_Enum.MEDIUM
        elif Risk_Enum.LOW     in risks: return Risk_Enum.LOW
        elif Risk_Enum.VERYLOW in risks: return Risk_Enum.VERYLOW
        elif Risk_Enum.NORISK  in risks: return Risk_Enum.NORISK
        else: return Risk_Enum.UNDEFINED


risk_matrix = [["3x2 Risk Matrix",   Complexity_Enum.LOW,     Complexity_Enum.HIGH ],
                [Impact_Enum.NONE,       Risk_Enum.LOW,       Risk_Enum.VERYLOW    ],
                [Impact_Enum.LOW,        Risk_Enum.MEDIUM,    Risk_Enum.MEDIUM     ],
                [Impact_Enum.HIGH,       Risk_Enum.VERYHIGH,  Risk_Enum.HIGH       ]]


class Risk():
    def __init__(self, id:str):
        self.id:str = id
        self.impact:Impact_Enum = Impact_Enum.UNKNOWN
        self.complexity:Complexity_Enum = Complexity_Enum.UNKNOWN
        self.risk:Risk_Enum = Risk_Enum.UNDEFINED

    def update_risk(self, id:int):
        self.id = "Risk_"+str(id).zfill(3)
        if self.impact   is Impact_Enum.NONE and self.complexity is Complexity_Enum.LOW:  self.risk = Risk_Enum.LOW
        elif self.impact is Impact_Enum.LOW  and self.complexity is Complexity_Enum.LOW:  self.risk = Risk_Enum.MEDIUM
        elif self.impact is Impact_Enum.HIGH and self.complexity is Complexity_Enum.LOW:  self.risk = Risk_Enum.VERYHIGH
        elif self.impact is Impact_Enum.NONE and self.complexity is Complexity_Enum.HIGH: self.risk = Risk_Enum.VERYLOW
        elif self.impact is Impact_Enum.LOW  and self.complexity is Complexity_Enum.HIGH: self.risk = Risk_Enum.MEDIUM
        elif self.impact is Impact_Enum.HIGH and self.complexity is Complexity_Enum.HIGH: self.risk = Risk_Enum.HIGH
        else: return Risk_Enum.UNDEFINED

    def set_no_risk(self):
        self.id = "No_Risk"
        self.risk = Risk_Enum.NORISK


class CVE():
    
    def __init__(self, cve_id:str, techniques_for_cve:dict):
        cvss_json = self.get_cvss_data(cve_id)
        self.cve_id:str = cve_id
        self.techniques:dict = techniques_for_cve
        if cvss_json is False:
            self.attack_vector:str = "Unknown"
            self.scope:str = "Unknown"
            self.complexity:Complexity_Enum = Complexity_Enum.UNKNOWN
            self.impact:Impact_Enum = Impact_Enum.UNKNOWN
        else:
            self.attack_vector:str = cvss_json["attackVector"]
            self.scope:str = cvss_json["scope"]
            self.complexity:Complexity_Enum = self.determine_complexity(cvss_json, cve_id)
            self.impact:Impact_Enum = self.determine_impact(cvss_json, cve_id)


    def get_cvss_data(self, cve_id:str):
        known_cves = json.load(open(setup.EXAMPLE_CVES_PATH))
        if cve_id in known_cves:
            # For Test only in order to reduce the number of requtests to the NIST NVD, as this is limited
            return known_cves[cve_id]
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id
        retry = 3
        response = requests.Request()
        while retry:
            response = requests.get(api_url)
            if response.status_code == 200:
                break
            elif response.status_code  == 403:
                print("HTTP REST Error: 403. Probably too many requests. URL:", api_url)
            else:
                print("HTTP REST Error: ", response.status_code, api_url)
            print("Please wait 30 Seconds for next request...", retry, "request attemp(s) left")
            time.sleep(30)
            retry-=1
            if retry == 0:
                print("Could not get information for", cve_id)
                return False
        response_json = response.json()
        metrics:dict = response_json["vulnerabilities"][0]["cve"]["metrics"]
        versions = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV20"]
        version = str()
        for version in versions:
            version_exist = metrics.get(version)
            if version_exist:
                break
            elif version == versions[-1]:
                print("Error: Unknown CVSS Metric Version for", cve_id)
                print("Checked for the following versions:", versions)
                return False
        cvss_json = metrics[version][0]["cvssData"]
        return cvss_json

    def determine_complexity(self, cvss_json, cve_id) -> Complexity_Enum:
        if cvss_json["attackComplexity"] in Complexity_Enum.LOW.value:
            return Complexity_Enum.LOW
        elif cvss_json["attackComplexity"] in Complexity_Enum.HIGH.value:
            return Complexity_Enum.HIGH
        else:
            raise ValueError("Unknown ComplexityEnum for", cve_id, cvss_json["attackComplexity"])

    def determine_impact(self, cvss_json, cve_id) -> Impact_Enum:
        c:str = cvss_json["confidentialityImpact"]
        i:str = cvss_json["integrityImpact"]
        a:str = cvss_json["availabilityImpact"]

        if c in Impact_Enum.HIGH.value or i in Impact_Enum.HIGH.value or a in Impact_Enum.HIGH.value:
            return Impact_Enum.HIGH
        elif c in Impact_Enum.LOW.value or i in Impact_Enum.LOW.value or a in Impact_Enum.LOW.value:
            return Impact_Enum.LOW
        elif c in Impact_Enum.NONE.value or i in Impact_Enum.NONE.value or a in Impact_Enum.NONE.value:
            return Impact_Enum.NONE
        else:
            raise ValueError("Unknown ImpactEnum for", cve_id, cvss_json["confidentialityImpact"], cvss_json["integrityImpact"], cvss_json["availabilityImpact"])
