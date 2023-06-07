import os
import zipfile
import json

from aggregator.config import Config
from aggregator.shared.singleton import SingletonMeta


class ResultService(metaclass=SingletonMeta):

    def __init__(self) -> None:
        self._config = Config()

    def extract_results(self, results_folder_name: str):
        """
        extracts results file from folder
        """
        results_folder = os.path.join(
            self._config.temp_folder, self._config.results_dir)
        results_zip_file_path = os.path.join(
            self._config.results_folder, results_folder_name, f"{results_folder_name}.zip")

        if os.path.exists(results_folder):
            return
        os.makedirs(results_folder)

        with zipfile.ZipFile(results_zip_file_path, 'r') as zip_file:
            zip_file.extractall(results_folder)

    def get_max_coverage_by_strategy(self, strategy: str, contracts: list):
        """
        returns the max coverage by strategy name
        """
        executions_by_contract_name = self._read_results_file(strategy)

        coverage_by_contract_name = self._init_result_dict(contracts)
        for contract in contracts:
            contract_name = contract["name"]
            coverage_by_contract_name[contract_name] = self._get_executions_average_coverage(
                executions_by_contract_name,
                contract_name,
                "maxCoverage",
            )

        sucessful_runs = [
            x for x in coverage_by_contract_name.values() if x != -1]
        coverage_sum = sum(sucessful_runs)
        successful_executions = len(sucessful_runs)

        average_coverage = (
            coverage_sum / successful_executions) if successful_executions > 0 else -1
        return (coverage_by_contract_name, average_coverage)

    def get_average_coverage_by_strategy(self, strategy: str, contracts: list):
        """
        returns the max coverage by strategy name
        """
        executions_by_contract_name = self._read_results_file(strategy)

        coverage_by_contract_name = self._init_result_dict(contracts)
        for contract in contracts:
            contract_name = contract["name"]
            coverage_by_contract_name[contract_name] = self._get_executions_average_coverage(
                executions_by_contract_name,
                contract_name,
                "averageCoverage",
            )

        sucessful_runs = [
            x for x in coverage_by_contract_name.values() if x != -1]
        coverage_sum = sum(sucessful_runs)
        successful_executions = len(sucessful_runs)

        average_coverage = (
            coverage_sum / successful_executions) if successful_executions > 0 else -1
        return (coverage_by_contract_name, average_coverage)

    def get_hits_by_strategy(self, strategy: str, contracts: list):
        """
        returns the critical instructions by strategy name
        """
        executions_by_contract_name = self._read_results_file(strategy)

        hits_by_contract_name = self._init_result_dict(contracts)
        for contract in contracts:
            contract_name = contract["name"]
            hits_by_contract_name[contract_name] = self._get_executions_hits_average(
                executions_by_contract_name,
                contract_name,
            )

        successful_executions = [
            x for x in hits_by_contract_name.values() if x != -1]
        hits_sum = sum(successful_executions)
        successful_executions = len(successful_executions)

        average_hits = (
            hits_sum / successful_executions) if successful_executions > 0 else -1
        return (hits_by_contract_name, average_hits)

    def get_detection_rate_by_strategy(
        self,
        strategy: str,
        contracts: list,
        vulnerabilities: list,
        include_new_detections: bool = True,
    ) -> map:
        """
        return the vulnerability detection rate by strategy name
        """
        executions_by_contract_name = self._read_results_file(strategy)

        pre_categorized_vulnerabilities = self._init_pre_categorized_vulnerabilities(
            contracts,
            vulnerabilities,
        )

        detection_rate = {}
        for vulnerability in vulnerabilities:
            detection_rate[vulnerability] = 0

        for contract in contracts:
            contract_name = contract["name"]
            contract_vulnerabilities = contract["vulnerabilities"]
            executions = executions_by_contract_name[contract_name]
            for execution in executions:
                detected_weaknesses = execution["execution"]["detectedWeaknesses"]
                for weakness in detected_weaknesses:
                    if weakness in vulnerabilities \
                            and (include_new_detections or weakness in contract_vulnerabilities):
                        detection_rate[weakness] += 1

        for vulnerability in detection_rate:
            if vulnerability in vulnerabilities:
                if include_new_detections and pre_categorized_vulnerabilities[vulnerability] == 0:
                    detection_rate[vulnerability] = detection_rate[vulnerability]
                elif pre_categorized_vulnerabilities[vulnerability] == 0:
                    detection_rate[vulnerability] = 0
                else:
                    detection_rate[vulnerability] = detection_rate[vulnerability] / \
                        pre_categorized_vulnerabilities[vulnerability]

        return detection_rate

    def _init_pre_categorized_vulnerabilities(self, contracts: list, vulnerabilities: list):
        pre_categorized_vulnerabilities = {}
        for vulnerability in vulnerabilities:
            pre_categorized_vulnerabilities[vulnerability] = 0

        for contract in contracts:
            for vulnerability in contract["vulnerabilities"]:
                if vulnerability not in pre_categorized_vulnerabilities:
                    pre_categorized_vulnerabilities[vulnerability] = 0
                pre_categorized_vulnerabilities[vulnerability] += 1
        return pre_categorized_vulnerabilities

    def _read_results_file(self, strategy: str) -> map:
        results_folder = os.path.join(
            self._config.temp_folder, self._config.results_dir)
        strategy_result_folder = os.path.join(
            results_folder, f"{strategy}_fuzzing")

        executions_by_contract_name = {}
        for path in os.listdir(strategy_result_folder):
            with open(os.path.join(strategy_result_folder, path), 'r', encoding='utf-8') as file:
                content = file.read()
                results_content = json.loads(content)
                for contract_name in results_content.keys():
                    executions = results_content[contract_name][strategy]
                    successful_executions = self._filter_successful_executions(
                        executions)
                    executions_by_contract_name[contract_name] = successful_executions
        return executions_by_contract_name

    def _filter_successful_executions(self, executions):
        filtered_executions = []
        for execution in executions:
            if execution["status"] == "success" and execution["execution"]["totalInstructions"] > 0:
                filtered_executions.append(execution)
        return filtered_executions

    def _init_result_dict(self, contracts: list):
        value = {}
        for contract in contracts:
            contract_name = contract["name"]
            if contract_name not in value:
                value[contract_name] = 0
        return value

    def _get_executions_average_coverage(
        self,
        executions: map,
        contract_name: str,
        coverage_type: str
    ) -> float:
        if contract_name not in executions or len(executions[contract_name]) == 0:
            return -1

        coverage_sum = 0
        for execution in executions[contract_name]:
            coverage = execution["execution"][coverage_type]
            total_instructions = execution["execution"]["totalInstructions"]
            coverage_sum += coverage / total_instructions
        return coverage_sum / len(executions[contract_name])

    def _get_executions_hits_average(self, executions: map, contract_name: str) -> float:
        if contract_name not in executions or len(executions[contract_name]) == 0:
            return -1
        hits = 0
        for execution in executions[contract_name]:
            hits += execution["execution"]["criticalInstructionsHits"]
        return hits / len(executions[contract_name])
