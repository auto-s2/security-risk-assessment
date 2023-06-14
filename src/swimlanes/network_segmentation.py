from domain_model.asset_classes import Machine
from domain_model.network_segmentation_classes import Conduit, Zone
from domain_model.network_segmentation_classes import Employee
import setup


def create_zones(machine:Machine) -> Machine:
    print("Definition of Zones for the machine as the System Under Consideration (SUC). Combines 'SuitableForSafetyFunctions' Assets and 'Non-SuitableForSafetyFunctions' Assets within the same Module into one Zone")
    for module in machine.hierarchy:
        zone_safety_id = "Zone_"+module.id_short+"_SuitableForSafetyFunctions"
        zone_safety = Zone(zone_safety_id, safety=True)
        zone_not_safety_id = "Zone_"+module.id_short
        zone_not_safety = Zone(zone_not_safety_id, safety=False)
        for component in module.hierarchy:
            if component.is_suitable_for_safety_functions:
                zone_safety.components.append(component)
            else:
                zone_not_safety.components.append(component)
        if len(zone_safety.components) > 0:
            zone_safety.accountable = Employee("0001", "AccountableEmployee", "inIT", "accountable.employee@init-owl.de", "+49 5261 7025788")
            zone_safety.responsible = Employee("0002", "ResponsibleEmployee", "inIT", "responsible.employee@init-owl.de", "+49 5261 7025080")
            module.zones.append(zone_safety)
        if len(zone_not_safety.components) > 0:
            zone_not_safety.accountable = Employee("0001", "AccountableEmployee", "inIT", "accountable.employee@init-owl.de", "+49 5261 7025788")
            zone_not_safety.responsible = Employee("0002", "ResponsibleEmployee", "inIT", "responsible.employee@init-owl.de", "+49 5261 7025080")
            module.zones.append(zone_not_safety)
    if setup.PRINT_RESULTS:
        for module in machine.hierarchy:
            print(module.id_short)
            for count_zone, zone in enumerate(module.zones, start=1):
                print("|-- Zone", count_zone, "=", zone.id)
                for countComponent, component in enumerate(zone.components, start=1):
                    print("    |-- Component", countComponent, "=", component.id_short)
                    for port in component.physical_port_endpoint_ids:
                        print("        |--", port.port_name, "Endpoint =", port.port_endpoint_id)
            if not module.zones:
                print("|-- No zones")
    return machine


def create_conduits(machine:Machine) -> Machine:
    print("Determine the physical connections of Assets. Create and save Conduits including AccessPoints and add the Conduits to each Zone based on the AccessPoints")
    test_conduit_count = 0
    for module in machine.hierarchy:
        for zone in module.zones:
            for component in zone.components:
                for ports in component.physical_port_endpoint_ids:
                    endpoint_aas_found = False
                    for module_compare in machine.hierarchy:
                        for zone_compare in module_compare.zones:
                            for component_compare in zone_compare.components:
                                if component_compare.id == ports.port_endpoint_id and zone.id != zone_compare.id:
                                    endpoint_aas_found = True
                                    # Sort by IdShort for naming
                                    if component.id_short < component_compare.id_short:
                                        access_point_1 = component
                                        access_point_2 = component_compare
                                    else:
                                        access_point_1 = component_compare
                                        access_point_2 = component
                                    conduit_id = "Conduit_"+access_point_1.id_short+"_"+access_point_2.id_short
                                    conduit_exists = False
                                    for condiut_compare in zone_compare.conduits:
                                        if condiut_compare.id == conduit_id:
                                            conduit_exists = True
                                            break
                                    if conduit_exists:
                                        conduit = condiut_compare
                                    else:
                                        conduit = Conduit(id=conduit_id)
                                        conduit.access_point_id_1 = access_point_1.id
                                        conduit.access_point_id_2 = access_point_2.id
                                        conduit.accountable = Employee("0001", "AccountableEmployee", "inIT", "accountable.employee@init-owl.de", "+49 5261 7025788")
                                        conduit.responsible = Employee("0002", "ResponsibleEmployee", "inIT", "responsible.employee@init-owl.de", "+49 5261 7025080")
                                        test_conduit_count+=1
                                    zone.conduits.append(conduit)
                                    component.is_access_point = True
                                elif component_compare.id == ports.port_endpoint_id and zone.id == zone_compare.id:
                                    endpoint_aas_found = True
                    if not endpoint_aas_found:
                        # Other entdpoint is unknow, probably a public network
                        conduit = Conduit(id="Conduit_"+component.id_short+"_PublicNetwork")
                        conduit.access_point_id_1 = component.id
                        conduit.access_point_id_2 = "UnknownComponent"
                        conduit.accountable = Employee("0001", "AccountableEmployee", "inIT", "accountable.employee@init-owl.de", "+49 5261 7025788")
                        conduit.responsible = Employee("0002", "ResponsibleEmployee", "inIT", "responsible.employee@init-owl.de", "+49 5261 7025080")
                        zone.conduits.append(conduit)
    if setup.PRINT_RESULTS:
        for module in machine.hierarchy:
            print(module.id_short)
            for zone in module.zones:
                print("|-- Zone =", zone.id)
                for conduit in zone.conduits:
                    print("    |-- Conduit =", conduit.id)
                    print("        |-- Accesspoint 1 =", conduit.access_point_id_1)
                    print("        |-- Accesspoint 2 =", conduit.access_point_id_2)
                if not zone.conduits:
                    print("    |-- No Conduits")
            if not module.zones:
                print("|-- No zones")
            print()
        print()
    return machine
