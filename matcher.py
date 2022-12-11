import difflib
import os
import json
import ssdeep
import argparse
import requests

import networkx as nx

from requests.auth import HTTPBasicAuth
from multiprocessing import Pool


parser = argparse.ArgumentParser(description="Match ACFG from BIN_FEATURE_DB")
parser.add_argument('-c', '--config', type=str, help='specify the config file', required=True)
parser.add_argument('-p', '--path', type=str, help='specify the BIN_FEATURE_DB path', required=True)
args = parser.parse_args()


class MatchGuy(object):

    def __init__(self, ExportedFuncsInfo: dict, FeatureDbPath: str, Arch: str, Config: dict, BinID: str):
        self.ZephyrBid = ["1", "5", "6", "7", "9", "11", "16", "19", "20"]
        self.LiteOSBid = ["13"]
        self.AliOSBid = ["12"]
        self.NuttxBid = ["18"]
        self.ExportedFuncsInfo = ExportedFuncsInfo
        self.FeatureDbTargetPath = [os.path.join(FeatureDbPath, "V1", Arch)]
        self.WhitelistFunctions = os.listdir(os.path.join(FeatureDbPath, "V1", Arch))
        self.Arch = Arch
        # if Arch == "mipsl":
        #     self.FeatureDbTargetPath.append(os.path.join(FeatureDbPath, "mipsb"))
        if BinID in self.ZephyrBid:
            print("add zephyr")
            self.FeatureDbTargetPath.append(os.path.join(
                FeatureDbPath, "V2", "Zephyr", Arch
            ))
        elif BinID in self.LiteOSBid:
            print("add liteos")
            self.FeatureDbTargetPath.append(os.path.join(
                FeatureDbPath, "V2", "LiteOS", Arch
            ))
        elif BinID in self.AliOSBid:
            print("add alios-things")
            self.FeatureDbTargetPath.append(os.path.join(
                FeatureDbPath, "V2", "AliOS-Things", Arch
            ))
        elif BinID in self.NuttxBid:
            print("add nuttx")
            self.FeatureDbTargetPath.append(os.path.join(
                FeatureDbPath, "V2", "Nuttx", Arch
            ))

        self.FeatureDb = {}
        self.Comparison = {}
        self.ComparisonFast = {}
        self.BetweennessDict = {
            "exported": {},
            "feature_db": {}
        }
        self.config = Config
        self.BinID = BinID
        for feature_db_target_path in self.FeatureDbTargetPath:
            if not os.path.exists(feature_db_target_path):
                print(f"BinDbTargetPath {feature_db_target_path} not exists")
                exit(1)
        self.to_output_function = [
            'atoi', 'checksum', 'csum', 'memcmp', 'memcpy', 'memmove', 'recvfrom', 'sendto', 'recv', 'send', 'snprintf',
            'sprintf', 'sscanf', 'strcat', 'strcmp', 'strcpy', 'strncat', 'strncmp', 'strncpy', 'strtol', 'getenv',
            'strchr', 'strlen', 'strnlen', 'strrchr', 'strtoul', 'memset'
        ]

    def initFeatureDbTarget(self):
        for feature_db_target_path in self.FeatureDbTargetPath:
            for func in os.listdir(feature_db_target_path):
                func_dir = os.path.join(feature_db_target_path, func)
                if func not in self.FeatureDb.keys():
                    self.FeatureDb[func] = {}
                for func_info_file in os.listdir(func_dir):
                    func_from = func_info_file.replace(".json", "")
                    func_info_path = os.path.join(func_dir, func_info_file)
                    self.FeatureDb[func][func_from] = json.load(open(func_info_path, "r"))
                    self.FeatureDb[func][func_from]["size"] = len(self.FeatureDb[func][func_from]["acfg"]["hash"])

    def diffOneFuncByFeatureDB(self, exported_func_id: str, exported_func: dict):

        if exported_func_id not in self.Comparison.keys():
            self.Comparison[exported_func_id] = {}
            self.ComparisonFast[exported_func_id] = {}

        for func in self.FeatureDb.keys():
            exported_func_name = exported_func_id[33:]
            if exported_func_name == func:
                self.Comparison[exported_func_id][func] = {}
                self.ComparisonFast[exported_func_id][func] = 1.0
                continue
            flunctation = round(len(exported_func["acfg"]["hash"]) / 16)
            max_size = len(exported_func["acfg"]["hash"]) + flunctation
            min_size = max(1, len(exported_func["acfg"]["hash"]) - flunctation)
            flag = False
            for feature_db_func_id in self.FeatureDb[func].keys():
                if min_size <= self.FeatureDb[func][feature_db_func_id]["size"] <= max_size:
                    flag = ~flag
                    break
            if not flag:
                continue
            if func not in self.Comparison[exported_func_id].keys():
                self.Comparison[exported_func_id][func] = {}
            tmp_cmp_list = []
            for feature_db_func_id in self.FeatureDb[func].keys():
                if min_size <= self.FeatureDb[func][feature_db_func_id]["size"] <= max_size:
                    # TODO: Filter by Graph Embedding Similarity
                    _, _, comparison = self.fastDiffFuncByBB(
                        exported_func_id, exported_func,
                        feature_db_func_id, self.FeatureDb[func][feature_db_func_id]
                    )
                    self.Comparison[exported_func_id][func][feature_db_func_id] = comparison
                    tmp_cmp_list.append(comparison["similarity"])
            self.ComparisonFast[exported_func_id][func] = max(tmp_cmp_list)
        return exported_func_id

    def matchFuncsByFeatureDB(self):

        in_limit = 0.75
        out_limit = 0.9

        G = nx.Graph()
        already_named = {}
        result = {}
        result_tmp = {}
        result_sim = {}

        for exported_func_id in self.ComparisonFast.keys():
            if exported_func_id[33:] in self.ComparisonFast[exported_func_id].keys():
                already_named[exported_func_id[33:]] = exported_func_id
        # print(json.dumps(already_named, indent=4))

        for exported_func_id in list(set(self.ComparisonFast.keys()) - set(already_named.values())):

            to_be_added_first = {}
            to_be_added_later = {}

            for feature_db_func in list(set(self.ComparisonFast[exported_func_id].keys()) - set(already_named.keys())):
                similarity = self.ComparisonFast[exported_func_id][feature_db_func]
                # if similarity > in_limit and "sub_" in exported_func_id:
                if similarity > in_limit and ("sub_" in exported_func_id or feature_db_func in exported_func_id):
                    to_be_added_first[feature_db_func] = similarity

            similarity_sorted_list = sorted(to_be_added_first, key=to_be_added_first.get, reverse=True)
            if len(similarity_sorted_list) > 2:
                to_be_added_later[similarity_sorted_list[0]] = to_be_added_first.get(similarity_sorted_list[0])
                to_be_added_later[similarity_sorted_list[1]] = to_be_added_first.get(similarity_sorted_list[1])
            else:
                to_be_added_later = to_be_added_first

            for feature_db_func in to_be_added_later.keys():
                G.add_edge(
                    exported_func_id, feature_db_func,
                    weight=to_be_added_later[feature_db_func]
                )

        matches = nx.max_weight_matching(G, maxcardinality=True)

        for match in matches:
            # print(match)
            for func in match:
                if func not in self.WhitelistFunctions:
                    exported_func_id = func
            for func in match:
                if func in self.WhitelistFunctions:
                    feature_db_func = func
            edge = G.get_edge_data(exported_func_id, feature_db_func)
            if edge is None:
                continue
            similarity = edge['weight']
            address = self.ExportedFuncsInfo[exported_func_id]["head"]
            if feature_db_func in self.to_output_function:
                result_sim[feature_db_func] = similarity
                result_tmp[feature_db_func] = address
                print(f'{self.BinID}:{feature_db_func}:{address:#x}\n\t'
                      f'({similarity:.4f}:{exported_func_id})')

        similarity_sorted_list = sorted(result_sim, key=result_sim.get, reverse=True)
        if len(similarity_sorted_list) > 1:
            if result_sim[similarity_sorted_list[1]] < out_limit:
                _tmp_out_limit = result_sim.get(similarity_sorted_list[1])
            else:
                _tmp_out_limit = out_limit
        elif len(similarity_sorted_list) == 1:
            _tmp_out_limit = result_sim.get(similarity_sorted_list[0])
        else:
            _tmp_out_limit = out_limit

        for feature_db_func in result_tmp.keys():
            if result_sim[feature_db_func] >= _tmp_out_limit:
                result[feature_db_func] = result_tmp.get(feature_db_func)

        for named in already_named.keys():
            exported_func_id = already_named[named]
            feature_db_func = named
            # similarity = self.ComparisonFast[exported_func_id][feature_db_func]
            address = self.ExportedFuncsInfo[exported_func_id]["head"]
            if feature_db_func in self.to_output_function:
                # result_sim[feature_db_func] = similarity
                result[feature_db_func] = address
                # print(f'{self.BinID}:{feature_db_func}:{address:#x}\n\t({similarity:.4f}:{exported_func_id})')

        for func in self.to_output_function:
            if func not in result.keys():
                result[func] = 0

        for func in result.keys():
            print(f'{self.BinID}:{func}:{result[func]:#x}')

        return result, result_tmp, already_named

    def diffFuncsByFeatureDB(self):

        for export_func_id in self.ExportedFuncsInfo.keys():
            self.diffOneFuncByFeatureDB(export_func_id, self.ExportedFuncsInfo[export_func_id])

    def calcBiEdgeWeight(self, block1, block2, hcfg1: dict, hcfg2: dict, betweenness1: dict, betweenness2: dict):

        cfg1, hash1, ea1, attr1 = hcfg1["cfg"], hcfg1["hash"], hcfg1["ea"], hcfg1["attr"]
        cfg2, hash2, ea2, attr2 = hcfg2["cfg"], hcfg2["hash"], hcfg2["ea"], hcfg2["attr"]

        numerator = 0
        denominator = 0
        # SSDEEP距离
        if (len(attr1[block1]["insts_list"]) <= 5 or len(attr2[block2]["insts_list"]) <= 5) \
                and not (len(cfg1.keys()) >= 2 and len(cfg2.keys()) >= 2):
            ssdeep_ratio = 5
            numerator += ssdeep_ratio * (100 - ssdeep.compare(hash2[block2], hash1[block1]))
            denominator += ssdeep_ratio * 100
        # 指令序列距离
        insts_r = 150 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 500
        if self.Arch in ["mipsl", "mipsb"]:
            insts_r = 50
            insts1 = set(attr1[block1]["insts_list"])
            insts2 = set(attr2[block2]["insts_list"])
            numerator += insts_r * (len(insts1 | insts2) - len(insts1 & insts2)) / len(insts1 | insts2)
            denominator += insts_r
        else:
            numerator += insts_r * (1 - difflib.SequenceMatcher(
                None, attr1[block1]["insts_list"], attr2[block2]["insts_list"]
            ).ratio())
            denominator += insts_r

        betweenness_r = 150 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 50
        offspring_r = 500 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 100
        # 中介中心度距离
        if max(betweenness2[block2], betweenness1[block1]) > 0:
            numerator += betweenness_r * abs(betweenness2[block2] - betweenness1[block1]) / max(betweenness2[block2], betweenness1[block1])
            denominator += betweenness_r
        # offspring数量差距
        if max(len(hcfg1["cfg"][block1]), len(hcfg2["cfg"][block2])) > 0:
            numerator += offspring_r * abs(len(hcfg1["cfg"][block1]) - len(hcfg2["cfg"][block2])) / max(len(hcfg1["cfg"][block1]), len(hcfg2["cfg"][block2]))
            denominator += offspring_r

        attrs = {
            "insts": 100 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 500,
            "calls": 100 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 200,
            "flags-jumps": 50,
            "equaled-jumps": 50,
            "signed-jumps": 50,
            "unsigned-jumps": 50,
            "arithmetic": 50,
            "logic": 50 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 100,
            "shift": 50 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 100,
            "system": 100 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 200,
            "ret": 100 if len(cfg1.keys()) >= 5 and len(cfg2.keys()) >= 5 else 200,
        }

        for key in attrs.keys():
            tmp_attr1 = 0 if key not in attr1[block1].keys() else attr1[block1][key]
            tmp_attr2 = 0 if key not in attr2[block2].keys() else attr2[block2][key]
            if max(tmp_attr1, tmp_attr2) > 0:
                numerator += attrs[key] * abs(tmp_attr2 - tmp_attr1) / max(tmp_attr1, tmp_attr2)
                denominator += attrs[key]

        if "consts" in attr1[block1].keys() and "consts" in attr2[block2].keys():
            consts1 = set(attr1[block1]["consts"])
            consts2 = set(attr2[block2]["consts"])

            if len(cfg1) == len(cfg2) <= 2:
                consts_ratio = 500
            else:
                consts_ratio = 200

            if len(consts1 | consts2) > 0:
                numerator += consts_ratio * (len(consts1 | consts2) - len(consts1 & consts2)) / len(consts1 | consts2)
                denominator += consts_ratio

        return numerator / denominator

    def calcCost4Matches(self, graph: nx.classes.graph.Graph, matches: set):
        cost = 0
        # max_cost = 0
        for match in matches:
            cost += graph.get_edge_data(match[0], match[1])['weight']
            # max_cost += 1
        return cost

    def fastDiffFuncByBB(self, exported_func_id: str, exported_func: dict, feature_db_func_id: str, feature_db_func: dict, debug=False):

        cfg1, hash1 = exported_func["acfg"]["cfg"], exported_func["acfg"]["hash"]
        cfg2, hash2 = feature_db_func["acfg"]["cfg"], feature_db_func["acfg"]["hash"]
        bipartite = {}

        if exported_func_id not in self.BetweennessDict["exported"].keys():
            if isinstance(cfg1, dict) and len(cfg1.keys()) > 20 \
                    and "CaaS" in self.config.keys() and "CaaS_PWD" in self.config.keys():
                try:
                    resp = requests.post(
                        url=f"{self.config['CaaS']}/betweenness",
                        json={"cfg": cfg1, "debug": "DEADBEEF" if debug else "NOP"},
                        auth=HTTPBasicAuth('admin', self.config["CaaS-PWD"])
                    )
                    self.BetweennessDict["exported"][exported_func_id] = json.loads(resp.text)
                except json.decoder.JSONDecodeError as e:
                    print(f"[response]: {resp.status_code}\t{e}")
                    self.BetweennessDict["exported"][exported_func_id] = nx.betweenness_centrality(nx.DiGraph(cfg1))
                except requests.exceptions.ConnectionError as e:
                    print(f"[connection]: {self.config['CaaS']}/betweenness failed\t{e}")
                    self.BetweennessDict["exported"][exported_func_id] = nx.betweenness_centrality(nx.DiGraph(cfg1))
            else:
                self.BetweennessDict["exported"][exported_func_id] = nx.betweenness_centrality(nx.DiGraph(cfg1))

        if feature_db_func_id not in self.BetweennessDict["feature_db"].keys():
            if isinstance(cfg2, dict) and len(cfg2.keys()) > 20 \
                    and "CaaS" in self.config.keys() and "CaaS_PWD" in self.config.keys():
                try:
                    resp = requests.post(
                        url=f"{self.config['CaaS']}/betweenness",
                        json={"cfg": cfg2, "debug": "DEADBEEF" if debug else "NOP"},
                        auth=HTTPBasicAuth('admin', self.config["CaaS-PWD"])
                    )
                    self.BetweennessDict["feature_db"][feature_db_func_id] = json.loads(resp.text)
                except json.decoder.JSONDecodeError as e:
                    print(f"[response]: {resp.status_code}\t{e}")
                    self.BetweennessDict["feature_db"][feature_db_func_id] = nx.betweenness_centrality(nx.DiGraph(cfg2))
                except requests.exceptions.ConnectionError as e:
                    print(f"[connection]: {self.config['CaaS']}/betweenness failed\t{e}")
                    self.BetweennessDict["feature_db"][feature_db_func_id] = nx.betweenness_centrality(nx.DiGraph(cfg2))
            else:
                self.BetweennessDict["feature_db"][feature_db_func_id] = nx.betweenness_centrality(nx.DiGraph(cfg2))

        for block2 in cfg2.keys():
            node2 = f"{block2}_2"
            bipartite[node2] = {}
            for block1 in cfg1.keys():
                node1 = f"{block1}_1"
                bipartite[node2][node1] = self.calcBiEdgeWeight(
                    block1, block2,
                    exported_func["acfg"], feature_db_func["acfg"],
                    self.BetweennessDict["exported"][exported_func_id],
                    self.BetweennessDict["feature_db"][feature_db_func_id]
                )

        _bipartite = nx.Graph()
        _bipartite = self.updateBipartite2Graph(_bipartite, bipartite)
        matches = nx.min_weight_matching(_bipartite)
        matches_cost = self.calcCost4Matches(_bipartite, matches)
        max_cost = min(len(hash1), len(hash2))
        similarity = 1 - (matches_cost / max_cost)

        return exported_func_id, feature_db_func_id, {
            "similarity": similarity,
            # TODO: add detail
        }

    def updateBipartite2Graph(self, graph: nx.classes.graph.Graph, bipartite: dict):
        for k in bipartite.keys():
            for k2 in bipartite[k].keys():
                graph.add_edge(k, k2, weight=bipartite[k][k2])
        return graph


def run(exported_path: str, arch: str, feature_db_path: str, config: str, bin_id: str, backup=True):

    if arch not in ["ARM", "metapc", "mipsl", "PPC", "PPCL", "riscv", "sparcb", "XTENSA", "arcv2", "s390x", "nios2"]:
        print("arch not support")
        return False, {}, {}

    if not os.path.exists(exported_path):
        print("no such file to be matched")
        return False, {}, {}

    if not os.path.exists(feature_db_path):
        print("no such bin_feature_db")
        return False, {}, {}

    if not os.path.exists(config):
        print("no such config")
        return False, {}, {}

    exported_funcs_info = {}

    for file in os.listdir(exported_path):
        if not file.endswith(".json"):
            continue
        loading_path = os.path.join(exported_path, file)
        exported_funcs_info[file[:-5]] = json.load(open(loading_path, "r"))

    matchguy = MatchGuy(
        ExportedFuncsInfo=exported_funcs_info,
        FeatureDbPath=feature_db_path,
        Arch=arch,
        BinID=bin_id,
        Config=json.load(open(config, "r"))
    )

    matchguy.initFeatureDbTarget()
    matchguy.diffFuncsByFeatureDB()
    result, result_sim, named = matchguy.matchFuncsByFeatureDB()
    if backup:
        json.dump(matchguy.Comparison, open(os.path.join(exported_path, "comparison.bak"), "w"))
        json.dump(matchguy.ComparisonFast, open(os.path.join(exported_path, "comparison_fast.bak"), "w"))
        json.dump(
            {"result": result, "raw_result": result_sim, "named": named},
            open(os.path.join(exported_path, "result.bak"), "w")
        )
    return True, matchguy.Comparison, matchguy.ComparisonFast


if __name__ == "__main__":

    test = True

    if not test:

        targets = {
            1: "sparcb",
            2: "PPCL",
            3: "ARM",
            4: "riscv",
            5: 'arcv2',
            6: "mipsl",
            7: "ARM",
            8: "ARM",
            9: "XTENSA",
            10: "metapc",
            11: "ARM",
            12: "ARM",
            13: "ARM",
            14: "ARM",
            15: 's390x',
            16: "riscv",
            17: "ARM",
            18: "ARM",
            19: "ARM",
            20: "nios2"
        }
        _args = []
        for k in targets.keys():
            bid = k
            arch = targets[k]
            _args.append((
                f"./rawdata/{arch}/{bid}",
                arch,
                args.path,
                args.config,
                str(k),
                True
            ))

        with Pool(6) as p:
            rets = p.starmap_async(run, _args).get()
            print(len(rets))
    else:
        arch = 'ARM'
        bid = 18
        run(
            f"./rawdata/{arch}/{bid}",
            arch,
            args.path,
            args.config,
            str(bid),
            True
        )
