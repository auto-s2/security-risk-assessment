from domain_model.asset_classes import Component, Machine
from domain_model.network_segmentation_classes import Zone
from domain_model.requirements_guarantees_classes import Mitre_Technique, Mitre_Technique_Level_Enum, SL_Status_Enum
from domain_model.risk_assessment_classes import CVE, Complexity_Enum, Impact_Enum, Risk_Enum
import copy
import setup

def collect_all_access_points(machine:Machine) -> Machine:
    print("Collect all Access Points")
    if setup.PRINT_RESULTS:
        for module in machine.hierarchy:
            for zone in module.zones:
                for component in zone.components:
                    if component.is_access_point:
                        print("|-- {:<22}".format(component.id_short), "in", zone.id)
    return machine

def collect_all_targets(machine:Machine) -> Machine:
    print("Collect all Assets which are SuitableForSafetyFunctions as Targets for possible impacts")
    for module in machine.hierarchy:
        for zone in module.zones:
            for component in zone.components:
                if component.is_suitable_for_safety_functions:    # Can easily be exteded with other attributes
                    component.is_target = True
    if setup.PRINT_RESULTS:
        for module in machine.hierarchy:
            for zone in module.zones:
                for component in zone.components:
                    if component.is_target:
                        print("|-- {:<22}".format(component.id_short), "in", zone.id)
    return machine


def collect_all_path_assets(machine:Machine):
    print("Collect all Path Assets with a direct network connection (Assets between an Access Point and Target)")
    for module in machine.hierarchy:
        for zone in module.zones:
            for component in zone.components:
                # Start with Access Point
                if component.is_access_point:
                    zone = follow_path(component, zone)
    if setup.PRINT_RESULTS:
        for module in machine.hierarchy:
            for zone in module.zones:
                for component in zone.components:
                    if component.is_path_asset:
                        print("|-- {:<22}".format(component.id_short), "in", zone.id)
    return machine


def follow_path(current_component:Component, zone:Zone) -> Zone:
    # Find the current component in the zone object to edit this
    for component in zone.components:
        if component.id == current_component.id:
            current_component.is_integrated_in_path = True
            # Check all Ports of the current component
            for port in component.physical_port_endpoint_ids:
                # Check all components in the Zone whether these are connected to the port
                for component_compare in zone.components:
                    if port.port_endpoint_id == component_compare.id:
                        # If the next hop is a target and not already part of a path is it a Path Asset
                        if component_compare.is_target and not component_compare.is_integrated_in_path:
                            # If the next hop is already assessed the algorithm would follow the path back again
                            # If the next hop is not a target, the current one remains as "not path" and the next is noted checked
                            component.is_path_asset = True
                            component.next_hops_ids_to_target.append(component_compare.id)
                            # So check the ports of the current path asset
                            zone = follow_path(component_compare, zone)
    return zone


def check_access_point_vulnerabilities(machine:Machine, techniques_for_cves:dict) -> Machine:
    print("(1) Get CVE information for all Access Points")
    print("Get relevant CVEs based on CVSS Attack Vector and CVSS Scope")
    print("Get MITRE Techniques which are mapped to the CVEs and collect all unmitigated CRs and SRs of the Access Point")
    print("Derive a list of possible MITRE Techniques based on the collected CRs and SRs")
    print("Compare MITRE Techniques for exploitation from the CVE mapping with the MITRE Techniques from the CRs and SRs")
    for module in machine.hierarchy:
        for zone in module.zones:
            if setup.PRINT_RESULTS:
                print("|--", zone.id)
            zone.access_points_secure = True
            for component in zone.components:
                if component.is_access_point:
                    relevant_cve_identified = False
                    cve_information_missing = False
                    if setup.PRINT_RESULTS:
                        print("    |-- Access Point:", component.id_short)
                        all_techniques:list[Mitre_Technique] = []
                    if len(component.cve_ids) == 0:
                        if setup.PRINT_RESULTS:
                            print("        |---> No CVE")
                    else:
                        for cve_id in component.cve_ids:
                            if cve_id in techniques_for_cves.keys():
                                cve = CVE(cve_id, techniques_for_cves[cve_id])
                                if cve.attack_vector.upper() == "Network".upper() and cve.scope.upper() == "Changed".upper() and Mitre_Technique_Level_Enum.EXPLOITATION in cve.techniques.keys():
                                    unmitig_techniques_before = len(component.techniques_unmitigated)
                                    component = add_unmitigated_techniques_to_component(component, zone, cve.techniques[Mitre_Technique_Level_Enum.EXPLOITATION])
                                    unmitig_techniques_after = len(component.techniques_unmitigated)
                                    relevant_cve_identified = True
                                    if setup.PRINT_RESULTS:
                                        all_techniques.extend(list(cve.techniques.values()))
                                        print("        |-- {:<14}".format(cve_id), "--> RELEVANT due to AttackVector = 'Network', Scope = 'Changed', and Technique for 'Exploitation' =", cve.techniques[Mitre_Technique_Level_Enum.EXPLOITATION].name, "- Adds", unmitig_techniques_after-unmitig_techniques_before, "new unmitigated Technique(s)")
                                else:
                                    if setup.PRINT_RESULTS:
                                        print("        |-- {:<14}".format(cve_id), "is NOT relevant - AttackVector: {:<16}".format(cve.attack_vector), "- Scope: {:<9}".format(cve.scope), "- Exploitation Technique exists:", (Mitre_Technique_Level_Enum.EXPLOITATION in cve.techniques.keys()))
                            else:
                                cve_information_missing = True
                                setup.error_list.append(cve_id + " is not assessed, because no Techniques assigned in AutoS² Information Base.")
                                if setup.PRINT_RESULTS:
                                    print(" ! ", setup.error_list[-1])
                        if relevant_cve_identified:
                            zone.access_points_secure = False
                            if setup.PRINT_RESULTS:
                                all_techniques = list(dict.fromkeys(all_techniques)) # Removes duplicates
                                print("        |---> Total", len(component.techniques_unmitigated), "relevant Technique(s) unmitigated:", [technique.name for technique in component.techniques_unmitigated])
                        if cve_information_missing == True:
                            if setup.PRINT_RESULTS:
                                print("        |---> CVE Information Missing. Check Errors!")
            # After checking all Access Points, and assessing them as secure, all component risks can be set to "No Risk"
            if zone.access_points_secure:
                for component in zone.components:
                    component.risk.set_no_risk()
    if setup.PRINT_RESULTS:
        print("Zones that are NOT secured by Access Points and are therefore further assessed:")
        for module in machine.hierarchy:
            for zone in module.zones:
                if not zone.access_points_secure:
                    print("|--", zone.id)
    return machine


def check_path_asset_vulnerabilities(machine:Machine, techniques_for_cves:dict) -> Machine:
    print("(2) Get CVE information for all Path Assets")
    print("ATTENTION: Only works for Line Network Topologies")
    print("Get relevant CVEs based on CVSS Attack Vector and CVSS Scope")
    print("Get MITRE Techniques which are mapped to the CVEs and collect all unmitigated CRs and SRs of the Path Asset")
    print("Derive a list of possible MITRE Techniques based on the collected CRs and SRs")
    print("Compare MITRE Techniques for exploitation from the CVE mapping with the MITRE Techniques from the CRs and SRs")
    for module in machine.hierarchy:
        for zone in module.zones:
            if setup.PRINT_RESULTS:
                print("|--", zone.id)
            # Only check zones that are not secured by the access points
            if not zone.access_points_secure:
                for component in zone.components:
                    # Start with the access point as the starting point
                    if component.is_access_point:
                        # Follow the next components as long as there is a next hop
                        while len(component.next_hops_ids_to_target) > 0:
                            for component_next in zone.components:
                                # If next component is not in the list of the next hop assets, is has not be checked
                                if component_next.id in component.next_hops_ids_to_target:
                                    # Find the next hop components
                                    for component_next_hop_id in component.next_hops_ids_to_target:
                                        # Next hop found
                                        if component_next.id == component_next_hop_id:
                                            if len(component.techniques_unmitigated) == 0 or component.is_protected_by_path and component_next.is_path_asset:
                                                # If the previous component has NO unmitigated techniques or is already protected, the following do not have to be checked.
                                                # If the current component ("componentNext") is not a path asset, the current one is assesed later on in the "TargetAssessment" function
                                                component_next.is_protected_by_path = True
                                                if setup.PRINT_RESULTS:
                                                    print("    |-- Path Asset:", component_next.id_short)
                                                    print("        |-- Protected by", component.id_short, "or previous component in path")
                                            elif len(component.techniques_unmitigated) > 0 and not component.is_protected_by_path and component_next.is_path_asset:
                                                # If the previous component has unmitigated techniques and not protected by path it is assessed as a path asset
                                                # If the current component ("componentNext") is not a path asset, the current one is assesed later on in the "TargetAssessment" function
                                                if setup.PRINT_RESULTS:
                                                    print("    |-- Path Asset:", component_next.id_short)
                                                    all_techniques:list[Mitre_Technique] = []  
                                                relevant_cve_identified = False
                                                cve_information_missing = False
                                                for cve_id in component_next.cve_ids:
                                                    if cve_id in techniques_for_cves.keys():
                                                        cve = CVE(cve_id, techniques_for_cves[cve_id])
                                                        if cve.attack_vector.upper() != "Physical".upper() and cve.scope.upper() == "Changed".upper() and cve.attack_vector.upper() != "Unknown".upper() and Mitre_Technique_Level_Enum.EXPLOITATION in cve.techniques.keys():
                                                            unmitig_techniques_before = len(component_next.techniques_unmitigated)
                                                            component_next = add_unmitigated_techniques_to_component(component_next, zone, cve.techniques[Mitre_Technique_Level_Enum.EXPLOITATION])
                                                            unmitig_techniques_after = len(component_next.techniques_unmitigated)
                                                            relevant_cve_identified = True
                                                            if setup.PRINT_RESULTS:
                                                                all_techniques.extend(list(cve.techniques.values()))
                                                                print("        |-- {:<14}".format(cve_id), "--> RELEVANT due to AttackVector not 'Physical', Scope = 'Changed', and Technique for 'Exploitation' =", cve.techniques[Mitre_Technique_Level_Enum.EXPLOITATION].name, "- Adds", unmitig_techniques_after-unmitig_techniques_before, "new unmitigated Technique(s)")
                                                        else:
                                                            if setup.PRINT_RESULTS:
                                                                print("        |-- {:<14}".format(cve_id), "is NOT relevant - AttackVector: {:<16}".format(cve.attack_vector), "- Scope: {:<9}".format(cve.scope), "- Exploitation Technique exists:", (Mitre_Technique_Level_Enum.EXPLOITATION in cve.techniques.keys()))
                                                    else:
                                                        cve_information_missing = True
                                                        setup.error_list.append(cve_id + " is not assessed, because no Techniques assigned in AutoS² Information Base.")
                                                        if setup.PRINT_RESULTS:
                                                            print(" ! ", setup.error_list[-1])
                                                if relevant_cve_identified == True:
                                                    if setup.PRINT_RESULTS:
                                                        all_techniques = list(dict.fromkeys(all_techniques)) # Removes duplicates
                                                        print("        |---> Total", len(component.techniques_unmitigated), "relevant Technique(s) unmitigated:", [technique.name for technique in component.techniques_unmitigated])
                                                if cve_information_missing == True:
                                                    if setup.PRINT_RESULTS:
                                                        print("        |---> CVE Information missing. Check Errors!")
                                            else:
                                                if setup.PRINT_RESULTS:
                                                    print("    |-- Asset:", component_next.id_short, "is not a Path Asset and is not protected by the path")
                                                    print("        |-- Will be assessed as a Target in the next step")
                                        # If next hop was found and assessed, do not continue searching and go to the next component
                                        break
                                # To avoid changes on componentNext, it is copied. Component is not changed
                                component = copy.copy(component_next)
            else:
                if setup.PRINT_RESULTS:
                    print("    |-- Protected by Access Points and not further assessed")
    return machine


def check_target_assets_vulnerabilities(machine:Machine, techniques_for_cves:dict) -> Machine:
    print("(3) Get CVE information for all Targets")
    print("ATTENTION: Only works for Line Network Topologies")
    print("Get relevant CVEs based on CVSS Attack Vector")
    print("Get MITRE Techniques which are mapped to the CVEs and collect all unmitigated CRs and SRs of the Targets")
    print("Derive a list of possible MITRE Techniques based on the collected CRs and SRs")
    print("Compare MITRE Techniques for exploitation from the CVE mapping with the MITRE Techniques from the CRs and SRs")
    for module in machine.hierarchy:
        for zone in module.zones:
            if setup.PRINT_RESULTS:
                print("|--", zone.id)
            if not zone.access_points_secure:
                for component in zone.components:
                    if component.is_target and not component.is_protected_by_path:
                        relevant_cve_identified = False
                        cve_information_missing = False
                        if setup.PRINT_RESULTS:
                            print("    |-- Target:", component.id_short)
                            all_techniques:list[Mitre_Technique] = []
                        for cve_id in component.cve_ids:
                            if cve_id in techniques_for_cves.keys():
                                cve = CVE(cve_id, techniques_for_cves[cve_id])
                                component.cves.append(cve)
                                if cve.attack_vector.upper() != "Physical".upper() and cve.attack_vector.upper() != "Unknown".upper() and Mitre_Technique_Level_Enum.EXPLOITATION in cve.techniques.keys():
                                    unmitig_techniques_before = len(component.techniques_unmitigated)
                                    component = add_unmitigated_techniques_to_component(component, zone, cve.techniques[Mitre_Technique_Level_Enum.EXPLOITATION])
                                    unmitig_techniques_after = len(component.techniques_unmitigated)
                                    relevant_cve_identified = True
                                    if setup.PRINT_RESULTS:
                                        all_techniques.extend(list(cve.techniques.values()))
                                        print("        |-- {:<14}".format(cve_id), "--> RELEVANT due to Attack Vector not 'Physical' and Technique for 'Exploitation' =", cve.techniques[Mitre_Technique_Level_Enum.EXPLOITATION].name, "- Adds", unmitig_techniques_after-unmitig_techniques_before, "new unmitigated Technique(s)")
                                else:
                                    if setup.PRINT_RESULTS:
                                        print("        |-- {:<14}".format(cve_id), "is NOT relevant - AttackVector: {:<16}".format(cve.attack_vector), "- Scope: {:<9}".format(cve.scope), "- Exploitation Technique exists:", (Mitre_Technique_Level_Enum.EXPLOITATION in cve.techniques.keys()))
                            else:
                                cve_information_missing = True
                                setup.error_list.append(cve_id + " is not assessed, because no Techniques assigned in AutoS² Information Base.")
                                if setup.PRINT_RESULTS:
                                    print(" ! ", setup.error_list[-1])
                        if relevant_cve_identified:
                            if setup.PRINT_RESULTS:
                                all_techniques = list(dict.fromkeys(all_techniques)) # Removes duplicates
                                print("        |---> Total", len(component.techniques_unmitigated), "relevant Technique(s) unmitigated:", [technique.name for technique in component.techniques_unmitigated])
                        else:
                            if setup.PRINT_RESULTS:
                                print("        |---> Target not relevant (no relevant CVEs identified)")
                        if cve_information_missing == True:
                            if setup.PRINT_RESULTS:
                                print("        |---> CVE Information missing. Check Errors!")
                        component.cves = list(dict.fromkeys(component.cves)) # Removes duplicates
                    else:
                        if setup.PRINT_RESULTS:
                            print("    |-- Asset:", component.id_short, "not a Target or protected by path")
            else:
                if setup.PRINT_RESULTS:
                    print("    |-- Protected by Access Points and not further assessed")
    return machine

def add_unmitigated_techniques_to_component(component:Component, zone:Zone, technique:Mitre_Technique):
    for mitigation in technique.mitigations:
        if zone.sl_status.cr_sr[mitigation.cr_sr] is SL_Status_Enum.UNMITIGATED:
            component.techniques_unmitigated.append(technique)
    component.techniques_unmitigated = list(dict.fromkeys(component.techniques_unmitigated)) # Removes duplicates
    return component


def determine_risks(machine:Machine):
    print("Collect all relevant Path Assets and the corresponding AccesPoints with unmitigated MITRE Techniques to define an attack path")   
    print("ATTENTION: Only works for Line Network Topologies")
    print("Determine the Impact for the Target based on the highest CVSS Impact (A, I, or C) of all CVEs for the Risk Assessment")
    print("Determine the Complexity for the Target based on the highest CVSS Attack Complexity (AC) from the whole attack path of Assets for the Risk Assessment")
    print("Determine the Resulting Risk and store the final Resulting Risk")
    risk_id:int = 1
    for module in machine.hierarchy:
        for zone in module.zones:
            if setup.PRINT_RESULTS:
                print("|--", zone.id)
            attack_path_possible = False
            # Only check zones that are not secured by the access points
            if not zone.access_points_secure:
                for component in zone.components:
                    # Start with the access point as the starting point
                    if component.is_access_point:
                        # Follow the next components as long as there is a next hop
                        previous_asset_complexity = Complexity_Enum.LOW # Initialize with low and raise later
                        # Get Complexity for Access Point
                        min_component_complexity = Complexity_Enum.HIGH # Initialize with high and lower later
                        max_impact:Impact_Enum = Impact_Enum.NONE
                        if setup.PRINT_RESULTS:
                            print("    |-- Target:", component.id_short, "with", len(component.techniques_unmitigated), "unmitigated Technique(s)")
                        if len(component.cves) > 0 and len(component.techniques_unmitigated) > 0:
                            for cve in component.cves:
                                if setup.PRINT_RESULTS:
                                    print("        |-- {:<14}".format(cve.cve_id), "- Impact:", cve.impact.name, "- Complexity:", cve.complexity.name)
                                # Find minimum complexity of all CVEs for the component
                                component.risk.complexity = Complexity_Enum.get_min(cve.complexity, min_component_complexity)
                                min_component_complexity = component.risk.complexity
                                # Get the maximum complexity of the path
                                component.risk.complexity = Complexity_Enum.get_max(previous_asset_complexity, min_component_complexity)
                                previous_asset_complexity = component.risk.complexity
                                # Assign the maximum impact to the component
                                component.risk.impact = Impact_Enum.get_max(cve.impact, max_impact)
                                max_impact = component.risk.impact
                            component.risk.update_risk(id=risk_id)
                            risk_id += 1
                            if setup.PRINT_RESULTS:
                                print("        |---> Component Impact:    ", max_impact.name)
                                print("        |---> Component Complexity:", min_component_complexity.name)
                                print("        |---> Path Complexity:     ", previous_asset_complexity.name)
                                print("        |-----> Resulting Risk:    ", component.risk.risk.name)
                        else:
                            component.risk.set_no_risk()
                            if setup.PRINT_RESULTS:
                                print("        |---> No CVE or no unmitigated Technique(s) for", component.id_short)
                        # Get complexity for all following Assets in a loop
                        while len(component.next_hops_ids_to_target) > 0:
                            for component_next in zone.components:
                                # If next component is not in the list of the next hop assets, is has not be checked
                                if component_next.id in component.next_hops_ids_to_target:
                                    # Find the next hop components
                                    for component_next_hop_id in component.next_hops_ids_to_target:
                                        # Next hop found
                                        if component_next.id == component_next_hop_id:
                                            # If the next hop is protected by the path, it does not have to be checked
                                            if setup.PRINT_RESULTS:
                                                    print("    |-- Target:", component_next.id_short, "with", len(component_next.techniques_unmitigated), "unmitigated Technique(s)")
                                            if component_next.is_target and not component_next.is_protected_by_path and len(component_next.techniques_unmitigated) > 0:
                                                attack_path_possible = True
                                                max_impact:Impact_Enum = Impact_Enum.NONE
                                                min_component_complexity = Complexity_Enum.HIGH # Initialize with high and lower later
                                                if len(component_next.cves) != 0:
                                                    for cve in component_next.cves:
                                                        if setup.PRINT_RESULTS:
                                                            print("        |-- {:<14}".format(cve.cve_id), "- Impact:", cve.impact.name, "- Complexity:", cve.complexity.name)
                                                        # Find minimum complexity of all CVEs for the component
                                                        component_next.risk.complexity = Complexity_Enum.get_min(cve.complexity, min_component_complexity)
                                                        min_component_complexity = component_next.risk.complexity
                                                        # Get the maximum complexity of the path
                                                        component_next.risk.complexity = Complexity_Enum.get_max(previous_asset_complexity, min_component_complexity)
                                                        previous_asset_complexity = component_next.risk.complexity
                                                        # Assign the maximum impact to the component
                                                        component_next.risk.impact = Impact_Enum.get_max(cve.impact, max_impact)
                                                        max_impact = component_next.risk.impact
                                                    component_next.risk.update_risk(risk_id)
                                                    risk_id += 1
                                                    if setup.PRINT_RESULTS:
                                                        print("        |---> Component Impact:    ", max_impact.name)
                                                        print("        |---> Component Complexity:", min_component_complexity.name)
                                                        print("        |---> Path Complexity:     ", previous_asset_complexity.name)
                                                        print("        |-----> Resulting Risk:    ", component.risk.risk.name)
                                                else:
                                                    component_next.risk.risk = Risk_Enum.NORISK
                                                    if setup.PRINT_RESULTS:
                                                        print("        |---> No CVE for", component.id_short)
                                            elif component_next.is_target and component_next.is_protected_by_path:
                                                component_next.risk.set_no_risk()
                                                if setup.PRINT_RESULTS:
                                                    print("        |---> Protected by Path Assets and not further assessed")
                                            elif component_next.is_target and len(component_next.techniques_unmitigated) == 0:
                                                component_next.risk.set_no_risk()
                                                if setup.PRINT_RESULTS:
                                                    print("        |---> Has no unmitigated Techniques and not further assessed")
                                            else:
                                                if setup.PRINT_RESULTS:
                                                    print("        |---> Unknown State. Target:", component_next.is_target, "| Protected by path:", component_next.is_protected_by_path, "| Unmitigated Technique(s):", len(component.techniques_unmitigated))
                                        # If next hop was found, do not continue searching and go to the next component
                                        break
                                # To avoid changes on componentNext, it is copied. Component is not changed
                                component = copy.copy(component_next)
            else:
                if setup.PRINT_RESULTS:
                    print("    |-- Protected by Access Points and not further assessed")
            if not attack_path_possible:
                if setup.PRINT_RESULTS:
                    print("    |---> No unprotected Target found in", zone.id)
    if setup.PRINT_RESULTS:
        print()
        print()
        for module in machine.hierarchy:
            for zone in module.zones:
                for component in zone.components:
                    if component.is_target:
                        if setup.PRINT_RESULTS:
                            print("|-- Component: {:<14}  Impact: {:<8}  Complexity: {:<8} -> {:<8}: {:<8}".format(component.id_short, component.risk.impact.name, component.risk.complexity.name, component.risk.id, component.risk.risk.name))
    return machine
