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

    def get_max_coverage_by_strategy(self, strategy: str):
        """
        returns the max coverage by strategy name
        """
        results_folder = os.path.join(
            self._config.temp_folder, self._config.results_dir)
        strategy_result_folder = os.path.join(
            results_folder, f"{strategy}_fuzzing")

        coverage_by_contract_name = {}
        executions_by_contract_name = {}
        for path in os.listdir(strategy_result_folder):
            with open(os.path.join(strategy_result_folder, path), 'r', encoding='utf-8') as file:
                content = file.read()
                results = json.loads(content)
                for contract_name in results.keys():
                    if contract_name not in coverage_by_contract_name:
                        coverage_by_contract_name[contract_name] = 0
                    if contract_name not in executions_by_contract_name:
                        executions_by_contract_name[contract_name] = 0

                    executions = results[contract_name][strategy]
                    for execution in executions:
                        if execution["status"] == "success" and execution["execution"]["totalInstructions"]:
                            coverage_by_contract_name[contract_name] += execution["execution"]["maxCoverage"] / \
                                execution["execution"]["totalInstructions"]
                            executions_by_contract_name[contract_name] += 1

        average_coverage = 0
        successful_executions = 0
        for contract_name in coverage_by_contract_name:
            if executions_by_contract_name[contract_name] == 0:
                coverage_by_contract_name[contract_name] = -1
                continue
            coverage_by_contract_name[contract_name] = coverage_by_contract_name[contract_name] / \
                executions_by_contract_name[contract_name]
            average_coverage += coverage_by_contract_name[contract_name]
            successful_executions += 1

        return (coverage_by_contract_name, average_coverage / successful_executions)

    def get_average_coverage_by_strategy(self, strategy: str):
        """
        returns the max coverage by strategy name
        """
        results_folder = os.path.join(
            self._config.temp_folder, self._config.results_dir)
        strategy_result_folder = os.path.join(
            results_folder, f"{strategy}_fuzzing")

        coverage_by_contract_name = {}
        executions_by_contract_name = {}
        for path in os.listdir(strategy_result_folder):
            with open(os.path.join(strategy_result_folder, path), 'r', encoding='utf-8') as file:
                content = file.read()
                results = json.loads(content)
                for contract_name in results.keys():
                    if contract_name not in coverage_by_contract_name:
                        coverage_by_contract_name[contract_name] = 0
                    if contract_name not in executions_by_contract_name:
                        executions_by_contract_name[contract_name] = 0

                    executions = results[contract_name][strategy]
                    for execution in executions:
                        if execution["status"] == "success" and execution["execution"]["totalInstructions"]:
                            coverage_by_contract_name[contract_name] += execution["execution"]["averageCoverage"] / \
                                execution["execution"]["totalInstructions"]
                            executions_by_contract_name[contract_name] += 1

        average_coverage = 0
        successful_executions = 0
        for contract_name in coverage_by_contract_name:
            if executions_by_contract_name[contract_name] == 0:
                coverage_by_contract_name[contract_name] = -1
                continue
            coverage_by_contract_name[contract_name] = coverage_by_contract_name[contract_name] / \
                executions_by_contract_name[contract_name]
            average_coverage += coverage_by_contract_name[contract_name]
            successful_executions += 1

        return (coverage_by_contract_name, average_coverage / successful_executions)

    def get_hits_by_strategy(self, strategy: str):
        """
        returns the critical instructions by strategy name
        """
        results_folder = os.path.join(
            self._config.temp_folder, self._config.results_dir)
        strategy_result_folder = os.path.join(
            results_folder, f"{strategy}_fuzzing")

        hits_by_contract_name = {}
        executions_by_contract_name = {}
        for path in os.listdir(strategy_result_folder):
            with open(os.path.join(strategy_result_folder, path), 'r') as file:
                content = file.read()
                results = json.loads(content)
                for contract_name in results.keys():
                    if contract_name not in hits_by_contract_name:
                        hits_by_contract_name[contract_name] = 0
                    if contract_name not in executions_by_contract_name:
                        executions_by_contract_name[contract_name] = 0

                    executions = results[contract_name][strategy]
                    for execution in executions:
                        if execution["status"] == "success":
                            hits_by_contract_name[contract_name] += execution["execution"]["criticalInstructionsHits"]
                            executions_by_contract_name[contract_name] += 1

        average_hits = 0
        successful_executions = 0
        for contract_name in hits_by_contract_name.keys():
            if executions_by_contract_name[contract_name] == 0:
                hits_by_contract_name[contract_name] = -1
                continue
            hits_by_contract_name[contract_name] = hits_by_contract_name[contract_name] / \
                executions_by_contract_name[contract_name]
            average_hits += hits_by_contract_name[contract_name]
            successful_executions += 1

        return (hits_by_contract_name, average_hits / successful_executions)

    def get_detection_rate_by_strategy(self, strategy: str, contracts: list, vulnerabilities: list, include_new_detections: bool = True) -> map:
        """
        return the vulnerability detection rate by strategy name
        """
        results_folder = os.path.join(
            self._config.temp_folder, self._config.results_dir)
        strategy_result_folder = os.path.join(
            results_folder, f"{strategy}_fuzzing")

        pre_categorized_vulnerabilities = {}
        for vulnerability in vulnerabilities:
            pre_categorized_vulnerabilities[vulnerability] = 0

        detection_rate = {}
        for vulnerability in vulnerabilities:
            detection_rate[vulnerability] = 0

        for path in os.listdir(strategy_result_folder):
            with open(os.path.join(strategy_result_folder, path), 'r') as file:
                content = file.read()
                results = json.loads(content)

                for contract in contracts:
                    for vulnerability in contract["vulnerabilities"]:
                        pre_categorized_vulnerabilities[vulnerability] += 1

                for contract_name in results.keys():
                    executions = results[contract_name][strategy]
                    for execution in executions:
                        if execution["status"] == "success":
                            for vulnerability in vulnerabilities:
                                if include_new_detections:
                                    if vulnerability in execution["execution"]["detectedWeaknesses"]:
                                        detection_rate[vulnerability] += 1
                                else:
                                    contract = None
                                    for c in contracts:
                                        if c["name"] == contract_name:
                                            contract = c
                                            break
                                    if vulnerability in execution["execution"]["detectedWeaknesses"] and vulnerability in contract["vulnerabilities"]:
                                        detection_rate[vulnerability] += 1

        for vulnerability in detection_rate.keys():
            detection_rate[vulnerability] = detection_rate[vulnerability] / \
                pre_categorized_vulnerabilities[vulnerability]

        return detection_rate
