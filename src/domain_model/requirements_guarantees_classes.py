from enum import Enum


class SL_Status_Enum(Enum):
    NODEFINITION = "NoDefinition"
    MITIGATED = "Mitigated"
    UNMITIGATED = "Unmitigated"
    TOBECHECKED = "ToBeChecked"
    SHIFTEDTOSYSTEM = "ShiftedToSystem"
    RECONFIGURATIONADVISED = "ReconfigurationAdvised"


class Mitre_Technique_Level_Enum(Enum):
    UNKNOWN = "Unknown"
    EXPLOITATION = "Exploitation"
    PRIMARYIMPACT = "Primary Impact"
    SECONDAYIMPACT = "Secondary Impact"


class Security_Level_Enum(Enum):
    SL_T = "SL-T"
    SL_A = "SL-A"
    SL_C = "SL-C"
    SL_STATUS = "SL-Status"


class Security_Level_IEC_62443():

    def __init__(self, security_level_type:str, system_or_component="Component", data_origin="AutoS²"):
        self.security_level_type:Security_Level_Enum = Security_Level_Enum(security_level_type)
        self.system_or_component:str = system_or_component
        self.data_origin:str = data_origin
        if security_level_type is Security_Level_Enum.SL_STATUS:
            default_value = SL_Status_Enum.NODEFINITION
        else:
            default_value = 0
        list_of_lengths = [14, 13, 14, 3, 4, 2, 8]
        self.cr_sr:dict = {  }
        for i in range(len(list_of_lengths)):
            temp = {f"{i+1}.{j+1}" : default_value for j in range(list_of_lengths[i])}
            self.cr_sr.update(temp)

    def print_vector(self):
        print(self.security_level_type.value)
        print(self.system_or_component)
        print(self.data_origin)
        for key, value in self.cr_sr.items():
            print("CR/SR", key, "--", self.security_level_type.value, value)
  
    def overwrite_cr_sr_with_value(self, value):
        for x in self.cr_sr:
            self.cr_sr[x] = value


class Mitre_Technique():

    def __init__(self, name:str, minimum_tal_skill:str, minimum_tal_resources:str):
        self.name:str = name
        self.minimum_tal_skill:str = minimum_tal_skill
        self.minimum_tal_resources:str = minimum_tal_resources
        self.mitigations:list[Mitre_Mitigation] = []
        self.sl_t = self.determine_sl_t(minimum_tal_skill, minimum_tal_resources)
        self.technique_level:list[Mitre_Technique_Level_Enum] = []

    def determine_sl_t(self, minimum_tal_skill, minimum_tal_resources) -> int:
        if minimum_tal_resources == "Individual":
            if minimum_tal_skill == "None":
                return 0
            elif minimum_tal_skill == "Minimal" or minimum_tal_skill == "Operational":
                return 1
            elif minimum_tal_skill == "Adept":
                return 2
            else:
                raise ValueError("Unknown minimumTalSkill ", minimum_tal_skill)
        elif minimum_tal_resources == "Club":
            if minimum_tal_skill == "None" or minimum_tal_skill == "Minimal" or minimum_tal_skill == "Operational":
                return 1
            elif minimum_tal_skill == "Adept":
                return 2
            else:
                raise ValueError("Unknown minimumTalSkill ", minimum_tal_skill)
        elif minimum_tal_resources == "Contest":
            if minimum_tal_skill == "None" or minimum_tal_skill == "Minimal":
                return 1
            elif minimum_tal_skill == "Operational" or minimum_tal_skill == "Adept":
                return 2
            else:
                raise ValueError("Unknown minimumTalSkill ", minimum_tal_skill)
        elif minimum_tal_resources == "Team":
            if minimum_tal_skill == "None" or minimum_tal_skill == "Minimal":
                return 2
            elif minimum_tal_skill == "Operational" or minimum_tal_skill == "Adept":
                return 3
            else:
                raise ValueError("Unknown minimumTalSkill ", minimum_tal_skill)
        elif minimum_tal_resources == "Organization":
            if minimum_tal_skill == "None":
                return 2
            elif minimum_tal_skill == "Minimal" or minimum_tal_skill == "Operational" or minimum_tal_skill == "Adept":
                return 3
            else:
                raise ValueError("Unknown minimumTalSkill ", minimum_tal_skill)
        elif minimum_tal_resources == "Government":
            if minimum_tal_skill == "None":
                return 2
            elif minimum_tal_skill == "Minimal" or minimum_tal_skill == "Operational":
                return 3
            elif minimum_tal_skill == "Adept":
                return 4
            else:
                raise ValueError("Unknown minimumTalSkill ", minimum_tal_skill)
        else:
            raise ValueError("Unknown minimumTalResources ", minimum_tal_resources)


class Mitre_Mitigation():

    def __init__(self, name:str, id:str, cr_sr:str):
        self.name:str = name
        self.id:str = id
        self.cr_sr:str = cr_sr
