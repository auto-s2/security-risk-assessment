from domain_model.requirements_guarantees_classes import Mitre_Technique, Security_Level_IEC_62443, SL_Status_Enum
from domain_model.asset_classes import Machine
import setup

def initialize_sl_status_vector(machine:Machine) -> Machine:
    print("Initialize all CR-Status and SR-Status with the default value 'NoDefinition'")
    for module in machine.hierarchy:
        for zone in module.zones:
            if hasattr(zone, 'sl_status'):
                zone.sl_status.overwrite_cr_sr_with_value(SL_Status_Enum.NODEFINITION)
            else:
                raise Exception(module.id_short, "has no SL-Status")
        for component in module.hierarchy:
            if hasattr(component, 'sl_status'):
                component.sl_status.overwrite_cr_sr_with_value(SL_Status_Enum.NODEFINITION)
            else:
                raise Exception(component.id_short, "has no SL-Status")
    return machine


def generate_mitre_sl_t_vector(all_mitre_techniques:list[Mitre_Technique]) -> Security_Level_IEC_62443:
    print("Check for highest SL-T from all linked MITRE Techniques")
    sl_t = Security_Level_IEC_62443("SL-T", "AllAssets", "MITRE")
    if setup.PRINT_RESULTS: 
        print("Before SL-T Assignment:", Security_Level_IEC_62443("SL-T", "AllAssets", "MITRE").cr_sr)
    for technique in all_mitre_techniques:
        for mitigation in technique.mitigations:
            for key, value in sl_t.cr_sr.items():
                if key == mitigation.cr_sr:
                    sl_t.cr_sr[key] = max(value, technique.sl_t)
    if setup.PRINT_RESULTS: 
        print("After SL-T Assignment: ", sl_t.cr_sr)
        print()
        print("Number of CRs/SRs:     ", len(sl_t.cr_sr))
    return sl_t


def initialize_sl_t_with_mitre_sl_t(machine:Machine, mitre_sl_t:Security_Level_IEC_62443) -> Machine:
    print("Assign the identified highest SL-T for the CR-ID and SR-ID. Assign the SL-T-Vector to the Components and Zones")
    for module in machine.hierarchy:
        for zone in module.zones:
            if hasattr(zone, 'sl_t'):
                zone.sl_t = mitre_sl_t
            else:
                raise Exception(zone.id, "has no SL-T")
        for component in module.hierarchy:
            if hasattr(component, 'sl_t'):
                component.sl_t = mitre_sl_t
            else:
                raise Exception(component.id_short, "has no SL-T")
    return machine


def evaluation_on_component_level(machine:Machine) -> Machine:
    print("Evaluate SL-T, SL-A and SL-C on Component-Level and assign Status for CRs")
    print("Change CR-Status to 'Shifted to System' and SR-Status to 'To be Checked', CR-Status to 'Mitigated', or CR-Status to 'Reconfiguration Advised'")
    count_shifted_to_system = 0
    count_mitigated = 0
    count_reconfiguration_advised = 0
    for module in machine.hierarchy:
        for zone in module.zones:
            for component in zone.components:
                for key in component.sl_c.cr_sr.keys():
                    # SL-C and SL-T:
                    if int(component.sl_c.cr_sr[key]) < int(component.sl_t.cr_sr[key]):
                        component.sl_status.cr_sr[key] = SL_Status_Enum.SHIFTEDTOSYSTEM
                        zone.sl_status.cr_sr[key] = SL_Status_Enum.TOBECHECKED
                        count_shifted_to_system += 1
                        # print("|-- CR/SR", key, "of", component.idShort, "-- Shifted to", module.idShort)
                    else:
                        # SL-A and SL-C
                        if int(component.sl_a.cr_sr[key]) < int(component.sl_c.cr_sr[key]):
                            component.sl_status.cr_sr[key] = SL_Status_Enum.RECONFIGURATIONADVISED
                            count_mitigated += 1
                            # print("|-- CR/SR", key, "of", component.idShort, "-- Reconfiguration advised")
                        else:
                            component.sl_status.cr_sr[key] = SL_Status_Enum.MITIGATED
                            count_reconfiguration_advised += 1
                            # print("|-- CR/SR", key, "of", component.idShort, "-- Mitigated")
    if setup.PRINT_RESULTS:
        print("|-- Shifted to System: {:>3}".format(count_shifted_to_system))
        print("|-- Mitigated:         {:>3}".format(count_mitigated))
        print("|-- Reconfig. Advised: {:>3}".format(count_reconfiguration_advised))
        # For manual evaluation: 58 CRs/SRs x 19 components = 1102 Status
    return machine


def get_sl_t_for_system(machine:Machine) -> Machine:
    print("Remove duplicate entries from the CRs with CR-Status 'Shifted to System' from different Assets within a zone and keep the maximum SL-T value for the whole zone")
    for module in machine.hierarchy:
        for zone in module.zones:
            count_shifted_to_system = 0
            for component in zone.components:
                for key, value in component.sl_status.cr_sr.items():
                    if value == SL_Status_Enum.SHIFTEDTOSYSTEM:
                        zone.sl_t.cr_sr[key] = max(int(zone.sl_t.cr_sr[key]), int(component.sl_t.cr_sr[key]))
                        count_shifted_to_system += 1
            if setup.PRINT_RESULTS:
                print("|-- Shifted to System: {:>3}".format(count_shifted_to_system), "in", zone.id)
                # For manual evaluation: 245 CRs/SRs in total
    return machine


def evaluation_on_system_level(machine:Machine) -> Machine:
    print("Evaluate SL-T, SL-A and SL-C on System/Zone-Level (check AccessPoint SLs of Zones) and assign Status for SRs")
    print("Mark SR-Status as 'Unmitigated', SR-Status as 'Mitigated', or SR-Status and CR-Status of Access Point to 'Reconfiguration Advised'")
    print("Only AccessPoints inside a Zone and of Zones with SR-Status 'ToBeChecked' are considered")
    count_mitigated = 0
    count_reconfiguration_advised = 0
    count_unmitigated = 0
    for module in machine.hierarchy:
        for zone in module.zones:
            # Nur die Conduits in der "eigenen" Zone werden weiter betrachtet. Nicht die Conduits in der benachbarten Zone
            for component in zone.components:
                if component.is_access_point == True:
                    for key in component.sl_c.cr_sr.keys():
                        if zone.sl_status.cr_sr[key] == SL_Status_Enum.TOBECHECKED:
                            # For multiple AccessPoints: Always overwrite with "Unmitigated"
                            if int(component.sl_c.cr_sr[key]) < int(zone.sl_t.cr_sr[key]):
                                zone.sl_status.cr_sr[key] = SL_Status_Enum.UNMITIGATED
                                count_unmitigated += 1
                            # For multiple AccessPoints: Only select "ReconfigurationAdvised" or "Mitigated" if not already marked as "Unmitigated"
                            elif zone.sl_status.cr_sr[key] != SL_Status_Enum.UNMITIGATED:
                                if int(component.sl_a.cr_sr[key]) < int(component.sl_c.cr_sr[key]):
                                    zone.sl_status.cr_sr[key] = SL_Status_Enum.RECONFIGURATIONADVISED
                                    # Identification of AccessPoint that has to be reconfigured is possible by Component SL-Status
                                    component.sl_status.cr_sr[key] = SL_Status_Enum.RECONFIGURATIONADVISED
                                    count_reconfiguration_advised += 1
                                elif zone.sl_status.cr_sr[key] != SL_Status_Enum.RECONFIGURATIONADVISED:
                                    zone.sl_status.cr_sr[key] = SL_Status_Enum.MITIGATED
                                    count_mitigated += 1
                                else:
                                    raise Exception("Unknown State")
                            else:
                                raise Exception("Unknown State")
    if setup.PRINT_RESULTS:
        print("|-- Mitigated by Access Points:          {:>4}".format(count_mitigated))
        print("|-- Reconfig. Advised for Access Points: {:>4}".format(count_reconfiguration_advised))
        print("|-- Unmitigated by Access Points:        {:>4}".format(count_unmitigated))
        # For manual evaluation: 18 Techniques x 5 AccessPoints = 90 in total
    return machine
