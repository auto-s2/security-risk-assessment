from domain_model.asset_classes import Machine
from domain_model.requirements_guarantees_classes import Mitre_Mitigation, Mitre_Technique
from swimlanes.attestation import create_attestation
from swimlanes.network_segmentation import create_conduits, create_zones
from swimlanes.autos2_information_base_reader import get_techniques_from_information_base, get_mitigations_from_information_base, assign_mitigations_to_technique, get_technique_dict_for_cves_from_information_base
from swimlanes.requirements_guarantees import generate_mitre_sl_t_vector, initialize_sl_status_vector, initialize_sl_t_with_mitre_sl_t, evaluation_on_component_level, get_sl_t_for_system, evaluation_on_system_level
from swimlanes.risk_assessment import check_access_point_vulnerabilities, check_path_asset_vulnerabilities, check_target_assets_vulnerabilities, collect_all_access_points, collect_all_path_assets, collect_all_targets, determine_risks
import time
import json
import setup

setup.initialize() 

selected = False
while not selected:
    print("Select:")
    print("1: Example 1 (with Risks)")
    print("2: Example 2 (some Risks are mitigated)")
    print("3: Example 3 (all Risks are mitigated)")
    print("0: Custom (select your own file)")
    number = input("Enter Number: ")

    if number == "1":
        path = setup.BASE_PATH + "/aas_examples/CPS_Example_1.json"
        selected = True
    elif number == "2":
        path = setup.BASE_PATH + "/aas_examples/CPS_Example_2.json"
        selected = True
    elif number == "3":
        path = setup.BASE_PATH + "/aas_examples/CPS_Example_3.json"
        selected = True
    elif number == "0":
        path = input("Enter path to AAS-JSON: ")
        selected = True
    else:
        print()
        print("Wrong number. Try again!")
        print()

if not setup.PRINT_RESULTS:
    print()
    print("No results shown in console")
    print()

# Open JSON with all AASs and Submodels of the machine
aass = json.load(open(path))
for aas in aass["assetAdministrationShells"]:
    if aas["idShort"] == setup.MACHINE_ID_SHORT:
        machine = Machine(aass_json=aass, aas=aas, id=aas["identification"]["id"])
        break
print(machine.id_short + ":")
for module in machine.hierarchy:
    print("|--", module.id_short)
    for component in module.hierarchy:
        print("    |--", component.id_short)
    if not module.hierarchy:
        print("    |-- No components found in AAS")

print()
print()

# The "machine" containing all AASs and submodels of the machine in scope is always handed to the functions, edited, and returned for the next step
start = time.time()

# Phase (1) Network Segmentation
print("---- Phase (1): Network Segmentation ----")
machine = create_zones(machine)
print()

machine = create_conduits(machine)
print()
print()

# Phase (2) Requirements Guarantees
print("---- Phase (2) Requirements Guarantees ----")
print()

# Override SL-Status that was read from AAS before:
machine = initialize_sl_status_vector(machine)
print()

# Read AutoS² Expert Knowledge
all_mitre_techniques:list[Mitre_Technique] = get_techniques_from_information_base(setup.EXCEL_AUTOS2_INFORMATION_BASE_PATH, setup.TAB_ICS_ATTACK_INTEL_TAL_MAPPING)
print()
all_mitre_mitigations:list[Mitre_Mitigation] = get_mitigations_from_information_base(setup.EXCEL_AUTOS2_INFORMATION_BASE_PATH, setup.TAB_MITIGATION_IEC_62443_MAPPING)
print()

# Read MITRE Knowledge
all_mitre_techniques = assign_mitigations_to_technique(setup.EXCEL_ICS_ATTACK_MITIGATIONS_PATH, setup.TAB_TECHNIQUES_ADDRESSED, all_mitre_techniques, all_mitre_mitigations)
print()

# Generate SL-T Vector based in MITRE Techniques
mitre_sl_t = generate_mitre_sl_t_vector(all_mitre_techniques)
print()

# Override SL-T that was read from AAS before:
machine = initialize_sl_t_with_mitre_sl_t(machine, mitre_sl_t)
print()

# Check the SL-Vectors of the components and assign SHIFTEDTOSYSTEM, TOBECHECKED, MITIGATED, or RECONFIGURATIONADVISED to the SL-Status of the component
machine = evaluation_on_component_level(machine)
print()

# Get the maximum SL-T for each CR that is shifted to the system level
machine = get_sl_t_for_system(machine)
print()

# Check the SL-Vectors of the zones and assign UNMITIGATED, MITIGATED, or RECONFIGURATIONADVISED to the SL-Status of the zone
machine = evaluation_on_system_level(machine)
print()
print()

print("---- Phase (3) Risk Assessment ----")
print()

# Get Technique List for CVEs from Excel
techniques_for_cves:dict = get_technique_dict_for_cves_from_information_base(setup.EXCEL_AUTOS2_INFORMATION_BASE_PATH, setup.TAB_CVE_ICS_MAPPING, all_mitre_techniques)
print()

# Collect all Access Points defined during creation of Conduits
machine = collect_all_access_points(machine)
print()

# Set Target for all "SuitableForSafety"-Assets that are no access points
machine = collect_all_targets(machine)
print()

# Set Path Assets for all assets between an Access Point and Target Asset. Remove "Target"-Bit for all Path Assets
machine = collect_all_path_assets(machine)
print()
print()
 
print("Start Risk Assessment for Access Points, Path Assets, and Targets")
print()

# Check Access Points
machine = check_access_point_vulnerabilities(machine, techniques_for_cves)
print()

# Check Path Assets
machine = check_path_asset_vulnerabilities(machine, techniques_for_cves)
print()

# Check Target Assets
machine = check_target_assets_vulnerabilities(machine, techniques_for_cves)
print()

# Determine Risk for each Target Asset
machine = determine_risks(machine)
print()
print()

print("---- Phase (4) Attestation ----")
print()

end = time.time()
computing_time = round(end-start, 2)
machine = create_attestation(machine, computing_time)
print()
print()
print()
