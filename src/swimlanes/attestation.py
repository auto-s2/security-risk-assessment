from datetime import datetime
from fpdf import FPDF
from domain_model.asset_classes import Machine
from domain_model.requirements_guarantees_classes import SL_Status_Enum
from domain_model.risk_assessment_classes import Risk_Enum
import os
import setup


def create_attestation(machine:Machine, computing_time:float) -> Machine:

    now = datetime.now()
    machine_hash = hash(machine)
    number_of_assets = 0
    number_of_zones = 0
    number_of_targets = 0
    number_of_unmitigated_srs = 0
    number_of_unmitigated_zones = 0
    number_of_reconfiguration_crs = 0
    number_of_reconfiguration_components = 0
    number_of_reconfiguration_srs = 0
    number_of_reconfiguration_zones = 0
    highest_risk = Risk_Enum.UNDEFINED
    (overall_minimum_tal_skill, overall_minimum_tal_resource) = get_lowest_attacker(machine)

    for module in machine.hierarchy:
        for component in module.hierarchy:
            number_of_assets += 1
            if component.is_target:
                number_of_targets += 1
                highest_risk = Risk_Enum.get_max(highest_risk, component.risk.risk)
            for cr_value in component.sl_status.cr_sr.values():
                cr_value:SL_Status_Enum
                if cr_value is SL_Status_Enum.RECONFIGURATIONADVISED:
                    number_of_reconfiguration_crs +=1
            if SL_Status_Enum.RECONFIGURATIONADVISED in component.sl_status.cr_sr.values():
                number_of_reconfiguration_components += 1
        for zone in module.zones:
            zone:zone
            number_of_zones += 1
            for sr_value in zone.sl_status.cr_sr.values():
                sr_value:SL_Status_Enum
                if sr_value is SL_Status_Enum.UNMITIGATED:
                    number_of_unmitigated_srs += 1
                elif sr_value is SL_Status_Enum.RECONFIGURATIONADVISED:
                    number_of_reconfiguration_srs +=1
            if SL_Status_Enum.RECONFIGURATIONADVISED in zone.sl_status.cr_sr.values():
                number_of_reconfiguration_zones += 1
            if SL_Status_Enum.UNMITIGATED in zone.sl_status.cr_sr.values():
                number_of_unmitigated_zones += 1
    setup.error_list = list(dict.fromkeys(setup.error_list))    # Remove Duplicates

    attestation_texts = {}
    attestation_texts["Date and Time of Attestation:"] = (now.strftime("%d.%m.%Y %H:%M:%S"),)
    attestation_texts["Attestation ID:"]               = (str(hex(abs(hash(str(machine_hash)+now.strftime("%d.%m.%Y %H:%M:%S"))))),)
    attestation_texts["Algorithm Computing Time:"]     = (str(computing_time) + " Seconds",)
    attestation_texts["Operator (Username):"]          = (os.getlogin(),)
    attestation_texts["Errors from the Algorithm:"]    = (str(len(setup.error_list)) + " Errors",)
    suc_texts = {}
    suc_texts["Total Number of Modules:"]         = (str(len(machine.hierarchy)),)
    suc_texts["Total Number of Components:"]      = (str(number_of_assets),)
    suc_texts["Total Number of Zones:"]           = (str(number_of_zones),)
    suc_texts["Total Number of Targets:"]         = (str(number_of_targets),)
    suc_texts["Total Number of Unmitigates SRs:"] = (str(number_of_unmitigated_srs), "in", str(number_of_unmitigated_zones), "Zones")
    suc_texts["Total Number of Reconf.Adv. SRs:"] = (str(number_of_reconfiguration_srs), "in", str(number_of_reconfiguration_zones), "Zones")
    suc_texts["Total Number of Reconf.Adv. CRs:"] = (str(number_of_reconfiguration_crs), "in", str(number_of_reconfiguration_components), "Components")
    results_texts = {}
    results_texts["Highest Risk of all Target Assets:"]                = (str(highest_risk.value),)
    results_texts["Lowest Intel TAL Attacker Skill (unmitigated):"]    = (str(overall_minimum_tal_skill),)
    results_texts["Lowest Intel TAL Attacker Resource (unmitigated):"] = (str(overall_minimum_tal_resource),)
    risks_dict = get_sorted_risks_dict(machine)
    
    print("Attestation:")
    for key, value in attestation_texts.items():
        print("- {:<30} {}".format(key, *value))
    for number, error in enumerate(setup.error_list):
        error = str(number+1) + ") " + error
        setup.error_list[number] = error
        print("                                 " + error)
    print()

    print("SuC:")
    for key, value in suc_texts.items():
        if len(value) == 1:
            print("- {:<32} {}".format(key, *value))
        elif len(value) == 4:
            print("- {:<32} {} {} {} {}".format(key, *value))
        else:
            print("- {:<32} {}".format(key, value))
    print()

    print("Results:")
    for key, value in results_texts.items():
        print("- {:<49} {}".format(key, *value))
    print()

    print("All Targets and Resulting Risks:")
    for key, value in risks_dict.items():
        value:Risk_Enum
        risks_dict[key] = ("with Risk", value)
        print("- {:<25} {}  {}".format(key, *risks_dict[key]))

    pdf = PDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf.titles("Attestation")

    pdf.text_block("Information", attestation_texts, 80)
    pdf.text_block("System under Consideration", suc_texts, 90)
    pdf.text_block("Results", results_texts, 120)
    pdf.text_block("All Targets and Resulting Risks", risks_dict, 84)

    pdf.image(setup.BASE_PATH + "/doc/AutoS2_Logo.png", x=150, y=20, w=40,h=40)

    if len(setup.error_list) > 0:
        pdf.add_page()
        pdf.subheader("Errors from the Algorithm:")
        pdf.errors_text()

    pdf.set_author('AutoS2 Automated Risk Assessment')
    pdf.output(setup.ATTEST_FILE_NAME, 'F')
    print()
    print("Attest File created:", setup.ATTEST_FILE_NAME)
    return machine


def get_lowest_attacker(machine:Machine):
    tal_skills_ordered = ["None", "Minimal", "Operational", "Adept"]
    tal_resources_ordered = ["Individual", "Club", "Contest", "Team", "Organization", "Government"]
    all_minimum_tal_skills = []
    all_minimum_tal_resources = []
    overall_minimum_tal_skill:str
    overall_minimum_tal_resource:str
    for module in machine.hierarchy:
        for component in module.hierarchy:
            for technique in component.techniques_unmitigated:
                all_minimum_tal_skills.append(technique.minimum_tal_skill)
                all_minimum_tal_resources.append(technique.minimum_tal_resources)
    for skill in tal_skills_ordered:
        if all_minimum_tal_skills == []:
            overall_minimum_tal_skill = "No Unmitigated Risk"
        if skill in all_minimum_tal_skills:
            overall_minimum_tal_skill = skill
    for resource in tal_resources_ordered:
        if all_minimum_tal_resources == []:
            overall_minimum_tal_resource = "No Unmitigated Risk"
        if resource in all_minimum_tal_resources:
            overall_minimum_tal_resource = resource
    return (overall_minimum_tal_skill, overall_minimum_tal_resource)


def get_sorted_risks_dict(machine:Machine) -> dict:
    targets_unsorted = { }
    targets_sorted = { }
    for module in machine.hierarchy:
        for component in module.hierarchy:
            if component.is_target:
                targets_unsorted[component.id_short] = component.risk.risk
    order = [Risk_Enum.VERYHIGH, Risk_Enum.HIGH, Risk_Enum.MEDIUM, Risk_Enum.LOW, Risk_Enum.VERYLOW, Risk_Enum.NORISK, Risk_Enum.UNDEFINED]
    for risk in order:
        for key, value in targets_unsorted.items():
            if value is risk:
                value:Risk_Enum
                targets_sorted[key] = value.value
    return targets_sorted


class PDF(FPDF):
    pass # nothing happens when it is executed.

    OFFSET_X = 10.0

    def titles(self, text:str):
        self.set_xy(0.0,0.0)
        self.set_font('Helvetica', 'B', 32)
        self.cell(w=210.0, h=20.0, align='C', txt=text)
        self.ln()

    def text_block(self, header:str, texts:dict, tab_size:int):
        WIDTH = 200.0
        HEIGHT = 6.0
        self.subheader(header)
        y = self.get_y()
        self.set_xy(self.OFFSET_X, y)
        self.set_font('Helvetica', 'B', 12)
        for key in texts.keys():
            self.cell(WIDTH, HEIGHT, key)
            self.ln()
        self.set_font('Helvetica', '', 12)
        self.set_y(y)
        for value in texts.values():
            self.set_x(tab_size)
            step = 0
            WIDTH_PER_CHAR = 4
            for item in value:
                item:str
                if item.isdigit():
                    align='R'
                    # Digits always have the same width for nice alignment
                    step_size = 3
                else:
                    align='L'
                    step_size = len(item)*WIDTH_PER_CHAR
                self.set_x(tab_size+step)
                self.cell(step_size, HEIGHT, item, align=align)
                step+=step_size
            self.ln()
        
    def subheader(self, header_text:str):
        self.set_xy(self.OFFSET_X, self.get_y())
        self.set_font('Helvetica', 'BU', 16)
        self.cell(100, 12, header_text)
        self.ln()

    def errors_text(self):
        self.set_xy(10.0, self.get_y())
        for error in setup.error_list:
            self.set_font('Helvetica', '', 12)
            self.multi_cell(180.0, 5.0, error)
            self.ln(3.0)
        self.ln()