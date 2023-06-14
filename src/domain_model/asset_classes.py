from typing import List
from domain_model.requirements_guarantees_classes import Security_Level_IEC_62443, Mitre_Technique
from domain_model.risk_assessment_classes import CVE, Risk
from domain_model.network_segmentation_classes import Zone


class Port():
    def __init__(self, port_name:str, port_endpoint_id:str):
        self.port_name:str = port_name
        self.port_endpoint_id:str = port_endpoint_id


class Asset():
    def __init__(self, aass_json, aas:dict, id:str):
        self.aas:dict = aas
        self.id:str = id
        self.id_short:str = aas["idShort"]
        self.submodels:List[dict] = self.get_submodels_from_submodel_list(aas, aass_json["submodels"])

    def get_submodels_from_submodel_list(self, aas:dict, all_submodels:List) -> List[dict]:
        submodel_list:List[dict] = []
        for submodel in aas["submodels"]:
            for keys in submodel["keys"]:
                submodel_id = keys["value"]
                for submodels in all_submodels:
                    if submodels["identification"]["id"] == submodel_id:
                        submodel_list.append(submodels)
        return submodel_list

    def get_submodel_by_id_short(self, id_short:str):
        for submodel in self.submodels:
            if submodel["idShort"]==id_short:
                return submodel

    def get_hierarchical_structure(self, aass_json:dict, type:str):
        hierarchy = self.get_submodel_by_id_short("HierarchicalStructures") # TODO: Get by SemanticID
        submodel_elements = hierarchy.get("submodelElements")
        if hierarchy is None or submodel_elements is None:
            return []
        aas_id_list:List[str] = []
        if type=="Machine":
            asset_list:List[Module] = []
        elif type=="Module":
            asset_list:List[Component] = []
        else:
            raise ValueError("Unknown type:", type)

        # TODO: Also check "HasPart" Relationship
        for submodel_element in submodel_elements:
            if submodel_element["semanticId"]["keys"][0]["value"] == "https://admin-shell.io/idta/HierarchicalStructures/ArcheType/1/0":
                if submodel_element["value"] != "OneDown":
                    raise ValueError("Wrong Structure in Hierarical Structre. ArcheType 'OneDown' not found (SemanticID https://admin-shell.io/idta/HierarchicalStructures/ArcheType/1/0)")
            elif submodel_element["semanticId"]["keys"][0]["value"] == "https://admin-shell.io/idta/HierarchicalStructures/EntryNode/1/0":
                current_aas_id = submodel_element["globalAssetId"]["keys"][0]["value"]
                for entity_statement_json in submodel_element["statements"]:
                    if   entity_statement_json["semanticId"]["keys"][0]["value"] == "https://admin-shell.io/idta/HierarchicalStructures/Node/1/0":
                        aas_id_list.append(entity_statement_json["globalAssetId"]["keys"][0]["value"])
                    # Additional check:
                    elif entity_statement_json["semanticId"]["keys"][0]["value"] == "https://admin-shell.io/idta/HierarchicalStructures/HasPart/1/0":
                        if entity_statement_json["first"]["keys"][0]["value"] != current_aas_id:
                            print("  ! Error in HierarchicalStructures:")
                            print("    First element of 'HasPart' Relationships does not equal EntryNodeID")
                            print("    Is", entity_statement_json["first"]["keys"][0]["value"], "... should be", current_aas_id)
                        if entity_statement_json["second"]["keys"][0]["value"] not in aas_id_list:
                            print("  ! Error in HierarchicalStructures:")
                            print("    Second element of 'HasPart' Relationships is not a Node in HierarchicalStructures: ", entity_statement_json["second"]["keys"][0]["value"])
                            print("    Check if all 'Nodes' are before Relationships in AAS?")

        for aas_id in aas_id_list:
            for aas in aass_json["assetAdministrationShells"]:
                if aas["identification"]["id"] == aas_id:
                    if type=="Machine":
                        asset_list.append(Module(aass_json, aas, aas_id))
                    elif type=="Module":
                        asset_list.append(Component(aass_json, aas, aas_id))
                    else:
                        raise ValueError("Unknown type:", type)
        return asset_list

    def get_aas_by_id(self, id:str) -> dict:
        for aas in self.hierarchy:
            if aas.id == id:
                return aas

    def print_hierarchical_structure(self):
        for aas in self.hierarchy:
            print(aas.id)

    def get_suitable_for_safety_functions_property(self) -> bool:
        misc_component_submodel = self.get_submodel_by_id_short("MiscComponentSubmodel")
        if misc_component_submodel is None:
            return False
        misc_component_submodel_elements = get_submodel_elements_from_submodel(misc_component_submodel)
        component_suitable_for_safety:str = get_submodel_element_value(misc_component_submodel_elements, "SuitableForSafetyFunctions")
        if component_suitable_for_safety.upper() == "TRUE":
            return True
        else:
            return False

    def get_physical_port_endpoint_ids(self) -> list[(str, str)]:
        physical_port_id_list:list[(str, str)] = ([])
        misc_component_submodel = self.get_submodel_by_id_short("MiscComponentSubmodel")
        if misc_component_submodel is None:
            return []
        misc_component_submodel_elements = get_submodel_elements_from_submodel(misc_component_submodel)
        physical_ports_smc = get_submodel_element_value(misc_component_submodel_elements, "PhysicalPorts")
        for physical_port in physical_ports_smc:
            physical_port_id_list.append(Port(port_name=physical_port["idShort"], port_endpoint_id=physical_port["value"]["keys"][0]["value"]))
        return physical_port_id_list

    def get_cve_ids(self) -> list[str]:
        cve_id_list:list[str] = []
        misc_component_submodel = self.get_submodel_by_id_short("MiscComponentSubmodel")
        if misc_component_submodel is None:
            return []
        misc_component_submodel_elements = get_submodel_elements_from_submodel(misc_component_submodel)
        cve_smc = get_submodel_element_value(misc_component_submodel_elements, "CVEs")
        for cve in cve_smc:
            cve_id_list.append(cve["value"])
        return cve_id_list

    def get_sl_from_aas(self, name:str) -> Security_Level_IEC_62443:
        security_submodel_found = False
        for submodel in self.submodels:
            if submodel["idShort"] == "SecurityLevelIEC62443":
                security_submodel_found = True
                if submodel["submodelElements"][0]["value"] == name:
                    sl = Security_Level_IEC_62443(submodel["submodelElements"][0]["value"], submodel["submodelElements"][1]["value"], submodel["submodelElements"][2]["value"]) 
                    for i in range(3, 10):
                        crs_srs = submodel["submodelElements"][i]["value"]
                        for cr_sr in crs_srs:
                            cr_sr_id:str = cr_sr["idShort"]
                            fr = cr_sr_id.split("_")[2]
                            rq = cr_sr_id.split("_")[3]
                            value = cr_sr["value"].split(".")[0]
                            # unavailable c_rs filled with 0
                            if value in ("0", "1", "2", "3", "4"):
                                sl.cr_sr[fr+"."+rq] = value
                            else:
                                sl.cr_sr[fr+"."+rq] = "0"
                    return sl
        if security_submodel_found:
            raise Exception("Unknown SecurityLevelIEC62443 Submodel", submodel["submodelElements"][0]["value"], name)


class Machine(Asset):
    def __init__(self, aass_json, aas:dict, id:str):
        super().__init__(aass_json, aas, id)
        self.hierarchy:List[Module] = self.get_hierarchical_structure(aass_json, type="Machine")
        self.level:str = "System"


class Module(Asset):
    def __init__(self, aass_json, aas:dict, id:str):
        super().__init__(aass_json, aas, id)
        self.hierarchy:List[Component] = self.get_hierarchical_structure(aass_json, type="Module")
        self.zones:List[Zone] = []
        self.level:str = "System"


class Component(Asset):
    def __init__(self, aass_json, aas:dict, id:str):
        super().__init__(aass_json, aas, id)
        self.level:str = "Component"
        self.is_suitable_for_safety_functions:bool = self.get_suitable_for_safety_functions_property()
        self.physical_port_endpoint_ids:List[Port] = self.get_physical_port_endpoint_ids()
        self.sl_t:Security_Level_IEC_62443 = Security_Level_IEC_62443("SL-T", "Component", "AutoS²") 
        self.sl_status:Security_Level_IEC_62443 = Security_Level_IEC_62443("SL-Status", "Component", "AutoS²") 
        self.sl_c:Security_Level_IEC_62443 = self.get_sl_from_aas("SL-C")
        self.sl_a:Security_Level_IEC_62443 = self.get_sl_from_aas("SL-A")
        self.cve_ids:List[str] = self.get_cve_ids()
        self.cves:List[CVE] = []
        self.is_access_point:bool = False
        self.is_target:bool = False
        self.is_path_asset:bool = False
        self.next_hops_ids_to_target:List[str] = []
        self.is_integrated_in_path:bool = False
        self.is_protected_by_path:bool = False
        self.techniques_unmitigated:List[Mitre_Technique] = []
        self.risk:Risk = Risk("DefaultRisk")


def get_submodel_elements_from_submodel(submodel) -> list[dict]:
    return submodel["submodelElements"]


def get_submodel_element_value(submodel_element, id_short) -> list[dict]:
    for sme in submodel_element:
        sme:dict
        if sme["idShort"] == id_short:
            return sme.get("value", [])
    return []
