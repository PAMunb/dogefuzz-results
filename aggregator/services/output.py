import os
import json
import numpy as np

from matplotlib import pyplot as plt
from sklearn.cluster import KMeans

from aggregator.config import Config

from aggregator.services.result import ResultService
from aggregator.shared.constants import BLACKBOX_FUZZING, DIRECTED_GREYBOX_FUZZING, GREYBOX_FUZZING
from aggregator.shared.singleton import SingletonMeta
from aggregator.shared.utils import map_vulnerability_to_dogefuzz_standard


class OutputService(metaclass=SingletonMeta):

    def __init__(self) -> None:
        self._config = Config()
        self._result_service = ResultService()

    def write_report(self, results_folder_name: str, contracts: list, for_smartian: bool):
        """
        writes the output to the output file
        """
        results_folder = os.path.join(
            self._config.results_folder, results_folder_name)

        critical_instructions = [
            "CALL",
            "SELFDESCTRUCT",
            "CALLCODE",
            "DELEGATECALL",
        ]

        if not for_smartian:        
            vulnerability_types = [
                "delegate",
                "exception-disorder",
                "gasless-send",
                "number-dependency",
                "reentrancy",
                "timestamp-dependency",
            ]
        else:
            vulnerability_types = [
                "ME",
                "RE",
                "BD",
            ]
            
        output_file_path = os.path.join(results_folder, "average.txt")

        if os.path.exists(output_file_path):
            os.remove(output_file_path)

        with open(output_file_path, "wt", encoding="utf-8") as f:
            self._write_line(f, 'AVERAGE RESULTS')
            self._write_transaction_count(f, contracts)
            self._write_max_coverage_result(f, contracts)
            self._write_average_coverage_result(f, contracts)
            # self._write_critial_instructions_hits(f, contracts)executions_by_contract_name[contract_name]
            self._write_critial_instructions_detailed_hits(
                f, contracts, critical_instructions)
            self._write_vulnerabilities(
                f, contracts, vulnerability_types, False)

        for vulnerability_type in vulnerability_types:
            file_path = os.path.join(
                results_folder, f"vulnerability-{vulnerability_type}.txt")
            if os.path.exists(file_path):
                os.remove(file_path)
            filtered_contracts = []
            for contract in contracts:
                for vulnerability in contract["vulnerabilities"]:
                    if vulnerability == vulnerability_type:
                        filtered_contracts.append(contract)
            with open(file_path, "wt", encoding="utf-8") as f:
                self._write_line(f, f'{vulnerability_type.upper()} RESULTS')
                self._write_max_coverage_result(f, filtered_contracts)
                self._write_average_coverage_result(f, filtered_contracts)
                # self._write_critial_instructions_hits(f, filtered_contracts)
                self._write_critial_instructions_detailed_hits(
                    f, filtered_contracts, critical_instructions)
                self._write_vulnerabilities(
                    f, filtered_contracts, [vulnerability_type], False)

        inputs_file = os.path.join(os.path.dirname(
            __file__), '..', '..', 'resources', 'inputs.json')

        dataset_array = []
        contracts_name = None
        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            contracts_name = [0] * len(inputs)
            for idx, contract in enumerate(inputs):
                contract_name = contract['name']
                contracts_name[idx] = contract_name
                row = [contract['numberOfBranches'], sum(
                    contract["numberOfCriticalInstructions"].values())]
                dataset_array.append(row)
        kmeans = KMeans(
            n_clusters=3,
            init='random',
            n_init=10,
            max_iter=100,
        )
        kmeans.fit(np.array(dataset_array))

        clusters = {}
        letters = ['A', 'B', 'C']
        for idx, cluster in enumerate(kmeans.labels_):
            key = letters[cluster]
            if key not in clusters:
                clusters[key] = []
            contract_info = [
                contract for contract in contracts if contract['name'] == contracts_name[idx]]
            if len(contract_info) > 0:
                clusters[key].append(contract_info[0])

        for key, contracts in clusters.items():
            file_path = os.path.join(
                results_folder, f"cluster-group-{key.lower()}.txt")
            if os.path.exists(file_path):
                os.remove(file_path)
            with open(file_path, "wt", encoding="utf-8") as f:
                self._write_line(f, f'GROUP {key.upper()} RESULTS')
                self._write_max_coverage_result(f, contracts)
                self._write_average_coverage_result(f, contracts)
                # self._write_critial_instructions_hits(f, contracts)
                self._write_critial_instructions_detailed_hits(
                    f, contracts, critical_instructions)
                self._write_vulnerabilities(
                    f, contracts, vulnerability_types, False)

    def _write_max_coverage_result(self, file, contracts: list):
        (max_coverage_per_contract_for_blackbox, average_coverage_for_blackbox) = self._result_service.get_max_coverage_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (max_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_max_coverage_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (max_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_max_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'MAX COVERAGE RESULTS', "contract")

        for contract in contracts:
            contract_name = contract["file"]
            blackbox = max_coverage_per_contract_for_blackbox[
                contract_name] if contract_name in max_coverage_per_contract_for_blackbox else -1
            greybox = max_coverage_per_contract_for_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_greybox else -1
            directed_greybox = max_coverage_per_contract_for_directed_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_directed_greybox else -1

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:45} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")

        self._write_average_footer(
            file,
            average_coverage_for_blackbox,
            average_coverage_for_greybox,
            average_coverage_for_directed_greybox,
        )

    def _write_average_coverage_result(self, file, contracts: list):
        (average_coverage_per_contract_for_blackbox, average_converage_for_blackbox) = self._result_service.get_average_coverage_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (average_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_average_coverage_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (average_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_average_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'AVERAGE COVERAGE RESULTS', "contract")

        for contract in contracts:
            contract_name = contract["file"]
            blackbox = average_coverage_per_contract_for_blackbox[
                contract_name] if contract_name in average_coverage_per_contract_for_blackbox else -1
            greybox = average_coverage_per_contract_for_greybox[
                contract_name] if contract_name in average_coverage_per_contract_for_greybox else -1
            directed_greybox = average_coverage_per_contract_for_directed_greybox[
                contract_name] if contract_name in average_coverage_per_contract_for_directed_greybox else -1

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:45} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")

        self._write_average_footer(
            file,
            average_converage_for_blackbox,
            average_coverage_for_greybox,
            average_coverage_for_directed_greybox,
        )

    def _write_critial_instructions_hits(self, file, contracts: list):
        (hits_per_contract_for_blackbox, average_hits_for_blackbox) = self._result_service.get_hits_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (hits_per_contract_for_greybox, average_hits_for_greybox) = self._result_service.get_hits_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (hits_per_contract_for_directed_greybox, average_hits_for_directed_greybox) = self._result_service.get_hits_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'CRITICAL INSTRUCTIONS HITS RESULTS', "instruction")

        for contract in contracts:
            contract_name = contract["file"]
            blackbox = hits_per_contract_for_blackbox[
                contract_name] if contract_name in hits_per_contract_for_blackbox else -1
            greybox = hits_per_contract_for_greybox[
                contract_name] if contract_name in hits_per_contract_for_greybox else -1
            directed_greybox = hits_per_contract_for_directed_greybox[
                contract_name] if contract_name in hits_per_contract_for_directed_greybox else -1

            hits_for_blackbox = self._convert_to_str(blackbox)
            hits_for_greybox = self._convert_to_diff_str(greybox, blackbox)
            hits_for_directed_greybox = self._convert_to_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:45} | {hits_for_blackbox:20} | {hits_for_greybox:20} | {hits_for_directed_greybox:20} |")
        self._write_average_number_footer(
            file,
            average_hits_for_blackbox,
            average_hits_for_greybox,
            average_hits_for_directed_greybox,
        )

    def _write_critial_instructions_detailed_hits(self, file, contracts: list, critical_instructions: list):
        (hits_per_instruction_for_blackbox, average_hits_for_blackbox) = self._result_service.get_hits_by_instructions_and_strategy(
            BLACKBOX_FUZZING,
            contracts,
            critical_instructions,
        )
        (hits_per_instruction_for_greybox, average_hits_for_greybox) = self._result_service.get_hits_by_instructions_and_strategy(
            GREYBOX_FUZZING,
            contracts,
            critical_instructions,
        )
        (hits_per_instruction_for_directed_greybox, average_hits_for_directed_greybox) = self._result_service.get_hits_by_instructions_and_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
            critical_instructions,
        )

        self._write_header(file, 'DETAILED CRITICAL INSTRUCTIONS HITS RESULTS', "instruction")

        for critical_instruction in critical_instructions:
            blackbox = hits_per_instruction_for_blackbox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_blackbox else -1
            greybox = hits_per_instruction_for_greybox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_greybox else -1
            directed_greybox = hits_per_instruction_for_directed_greybox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_directed_greybox else -1

            hits_for_blackbox = self._convert_to_str(blackbox)
            hits_for_greybox = self._convert_to_diff_str(greybox, blackbox)
            hits_for_directed_greybox = self._convert_to_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {critical_instruction:45} | {hits_for_blackbox:20} | {hits_for_greybox:20} | {hits_for_directed_greybox:20} |")

        self._write_average_number_footer(
            file,
            average_hits_for_blackbox,
            average_hits_for_greybox,
            average_hits_for_directed_greybox,
        )

    def _write_vulnerabilities(
        self,
        file,
        contracts: list,
        vulnerability_types: list,
        include_new_detections: bool = False,
    ):
        detection_rate_for_blackbox = self._result_service.get_detection_rate_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )
        detection_rate_for_greybox = self._result_service.get_detection_rate_by_strategy(
            GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )
        detection_rate_for_directed_greybox = self._result_service.get_detection_rate_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )

        self._write_header(file, 'VULNERABILITIES RESULTS', "vulnerability type")
        
        vul_count = self._result_service.get_vulnerabilities_count(contracts, vulnerability_types)
     
        average_detection_rate_for_blackbox = 0
        average_detection_rate_for_greybox = 0
        average_detection_rate_for_directed_greybox = 0
        
        total_blackbox = 0
        total_greybox = 0
        total_directed_greybox = 0
        
        for vulnerability in vulnerability_types:
            blackbox = detection_rate_for_blackbox[vulnerability][0]
            greybox = detection_rate_for_greybox[vulnerability][0]
            directed_greybox = detection_rate_for_directed_greybox[vulnerability][0]

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str_with_total(
                greybox, blackbox, detection_rate_for_greybox[vulnerability][1])
            percentage_directed_greybox = self._convert_to_percentage_diff_str_with_total(
                directed_greybox, blackbox, detection_rate_for_directed_greybox[vulnerability][1])

            average_detection_rate_for_blackbox += blackbox
            average_detection_rate_for_greybox += greybox
            average_detection_rate_for_directed_greybox += directed_greybox

            total_blackbox += detection_rate_for_blackbox[vulnerability][1]
            total_greybox += detection_rate_for_greybox[vulnerability][1]
            total_directed_greybox += detection_rate_for_directed_greybox[vulnerability][1]
            
            vulnerability_text = vulnerability + " (" + str(vul_count[vulnerability]) + ")"
            percentage_blackbox_text = percentage_blackbox + " (" + str(detection_rate_for_blackbox[vulnerability][1]) + ")"
            
            self._write_line(
                file, f"| {vulnerability_text:45} | {percentage_blackbox_text:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")

        average_blackbox = average_detection_rate_for_blackbox / \
            len(vulnerability_types)
        average_greybox = average_detection_rate_for_greybox / \
            len(vulnerability_types)
        average_directed_greybox = average_detection_rate_for_directed_greybox / \
            len(vulnerability_types)

        if (len(vulnerability_types) > 1):
            self._write_average_footer_with_total(
                file, sum(vul_count.values()),
                average_blackbox, total_blackbox,
                average_greybox, total_greybox,
                average_directed_greybox, total_directed_greybox
            )
        else:
            self._write_dashed_line(file)

    def _write_transaction_count(self, file, contracts: list):
        transaction_count_for_blackbox = self._result_service.get_transaction_count_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        transaction_count_for_greybox = self._result_service.get_transaction_count_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        transaction_count_for_directed_greybox = self._result_service.get_transaction_count_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'TRANSACTION COUNT RESULTS', "count")

        blackbox = self._convert_to_str(transaction_count_for_blackbox)
        greybox = self._convert_to_diff_str(
            transaction_count_for_greybox, transaction_count_for_blackbox)
        directed_greybox = self._convert_to_diff_str(
            transaction_count_for_directed_greybox, transaction_count_for_blackbox)

        self._write_line(
            file, f"| {'transaction_count':45} | {blackbox:20} | {greybox:20} | {directed_greybox:20} |")

        self._write_dashed_line(file)

    def _write_header(self, file, title: str, text: str):
        self._write_line(file, "\n")
        self._write_line(file, title)
        self._write_dashed_line(file)
        self._write_line(
            file, f"| {text:45} | {'blackbox':20} | {'greybox':20} | {'directed_greybox':20} |")
        self._write_dashed_line(file)

    def _write_average_footer(
        self,
        file,
        average_blackbox,
        average_greybox,
        average_directed_greybox,
    ):
        percentage_blackbox = self._convert_to_percentage_str(average_blackbox)
        percentage_greybox = self._convert_to_percentage_diff_str(
            average_greybox, average_blackbox)
        percentage_directed_greybox = self._convert_to_percentage_diff_str(
            average_directed_greybox, average_blackbox)

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'AVERAGE':45} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _write_average_footer_with_total(
        self,
        file, total_vulnerabilities,
        average_blackbox, total_blackbox,
        average_greybox, total_greybox,
        average_directed_greybox, total_directed_greybox
    ):
        percentage_blackbox = self._convert_to_percentage_str(average_blackbox)
        percentage_greybox = self._convert_to_percentage_diff_str_with_total(
            average_greybox, average_blackbox, total_greybox)
        percentage_directed_greybox = self._convert_to_percentage_diff_str_with_total(
            average_directed_greybox, average_blackbox, total_directed_greybox)


        percentage_blackbox_text = percentage_blackbox + " (" + str(total_blackbox) + ")"
        total_vulnerabilities_text = "AVERAGE" + " (" + str(total_vulnerabilities) + ")"

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {total_vulnerabilities_text:45} | {percentage_blackbox_text:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _write_average_number_footer(
        self,
        file,
        average_blackbox,
        average_greybox,
        average_directed_greybox,
    ):
        number_blackbox = self._convert_to_str(average_blackbox)
        number_greybox = self._convert_to_diff_str(
            average_greybox, average_blackbox)
        number_directed_greybox = self._convert_to_diff_str(
            average_directed_greybox, average_blackbox)

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'AVERAGE':45} | {number_blackbox:20} | {number_greybox:20} | {number_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _convert_to_str(self, value) -> str:
        return f"{value:.2f}" if value != -1 else "N/A"

    def _convert_to_percentage_str(self, value) -> str:
        return f"{value * 100:.2f}%" if value != -1 else "N/A"

    def _convert_to_diff_str(self, value, base_value) -> str:
        if base_value == 0:
            diff = 1 if value != 0 else 0
        else:
            diff = (value - base_value) / base_value
        return f"{value:.2f} ({'+' if diff > 0 else ''}{diff * 100:.2f}%)" if value != -1 else "N/A"

    def _convert_to_percentage_diff_str(self, value, base_value) -> str:
        if base_value == 0:
            diff = 1 if value != 0 else 0
        else:
            diff = (value - base_value) / base_value
        return f"{value * 100:.2f}% ({'+' if diff > 0 else ''}{diff * 100:.2f}%)" if value != -1 else "N/A"

    def _convert_to_percentage_diff_str_with_total(self, value, base_value, total) -> str:
        if base_value == 0:
            diff = 1 if value != 0 else 0
        else:
            diff = (value - base_value) / base_value
        return f"{value * 100:.2f}% ({total:02d},{'+' if diff > 0 else ''}{diff * 100:.2f}%)" if value != -1 else "N/A"


    def _write_dashed_line(self, file):
        self._write_line(file, '-' * 118)

    def _write_line(self, file, line: str):
        file.write(line + '\n')
