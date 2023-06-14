from typing import List
from domain_model.requirements_guarantees_classes import Security_Level_IEC_62443
import domain_model.asset_classes


class Zone():

    def __init__(self, id, safety):
        self.id:str = id
        self.conduits:List[Conduit] = []
        self.components:List[domain_model.asset_classes.Component] = []
        self.accountable:Employee
        self.responsible:Employee
        self.safety:bool = safety
        self.sl_t:Security_Level_IEC_62443 = Security_Level_IEC_62443("SL-T", "System", "AutoS²")
        self.sl_c:Security_Level_IEC_62443 = Security_Level_IEC_62443("SL-C", "System", "AutoS²")
        self.sl_a:Security_Level_IEC_62443 = Security_Level_IEC_62443("SL-A", "System", "AutoS²")
        self.sl_status:Security_Level_IEC_62443 = Security_Level_IEC_62443("SL-Status", "System", "AutoS²")
        self.access_points_secure:bool = False


class Conduit():

    def __init__(self, id):
        self.id:str = id
        self.accountable:Employee
        self.responsible:Employee
        self.access_point_id_1:str
        self.access_point_id_2:str


class Employee():

    def __init__(self, id, name, company, email, telephone):
        self.id:str = id
        self.name:str = name
        self.company:str = company
        self.email:str = email
        self.telephone:str = telephone
