import json
import os
import random

BASE_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__)))

selected = False
while not selected:
    print("Select: Update SL-A and SL-T of")
    print("1: CPS_Example_1.json")
    print("0: Custom (select your own file)")
    number = input("Enter Number: ")

    if number == "1":
        path = BASE_PATH + "/CPS_Example_1.json"
        selected = True
    elif number == "0":
        path = input("Enter path to AAS-JSON1: ")
        selected = True
    else:
        print()
        print("Wrong number. Try again!")
        print()

aass = json.load(open(path))

cr_sr_range = (0, 3)
cr_sr_distribution_sl_a = []
for i in range(cr_sr_range[0], cr_sr_range[1]+1):
    cr_sr_distribution_sl_a.append(0)
cr_sr_distribution_sl_c = []
for i in range(cr_sr_range[0], cr_sr_range[1]+1):
    cr_sr_distribution_sl_c.append(0)
sl_c = []

submodels = aass["submodels"]
for submodel in submodels:
    if "SecurityLevelIEC62443" in submodel["idShort"]:
        submodelElements = submodel["submodelElements"]
        for element in submodelElements:
            if "SL_" in element["idShort"]:
                sl = element["idShort"]
                sl_smc = element["value"]
                for value in sl_smc:
                    if "Level" in value["idShort"]:
                        if not "Component" in value["value"]:
                            print("SL Vector not for Component: Level =", value["value"])
                            print("Skip Submodel", submodel["identification"]["id"])
                            break
                    if "FR_" in value["idShort"]:
                        crs = value["value"]
                        position = 0
                        for cr in crs:
                            if sl == "SL_C":
                                upper_bound = cr_sr_range[1]
                            elif sl == "SL_A":
                                upper_bound = sl_c[position]    # Avoid State with SL-A > SL-C
                            else:
                                print("Unexpected SL:", sl)
                                print("Skip Submodel", submodel["identification"]["id"])
                                break
                            new_sl = random.randint( cr_sr_range[0], upper_bound)
                            cr["value"] = str(new_sl)
                            sl_c.append(new_sl)
                            if sl == "SL_C":
                                cr_sr_distribution_sl_c[new_sl] += 1
                            if sl == "SL_A":
                                cr_sr_distribution_sl_a[new_sl] += 1
    sl_c = [] # Clear SL-C for next Submodel / Component
print()

for i in range(len(cr_sr_distribution_sl_a)):
    print("SL-C=" + str(i) + ":", str(cr_sr_distribution_sl_c[i]) + "-times \t SL-A=" + str(i) + ":", str(cr_sr_distribution_sl_a[i]) + "-times")
print()

new_file_path = path.removesuffix(".json")+"_random_SL_Values.json"
with open(new_file_path, "w") as f:
    json.dump(aass, f)
    print("Saved new file", new_file_path)