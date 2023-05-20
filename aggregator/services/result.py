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
        results_folder = os.path.join(self._config.temp_folder, self._config.results_dir)
        results_zip_file_path = os.path.join(self._config.results_folder, results_folder_name, f"{results_folder_name}.zip")

        if os.path.exists(results_folder):
            return
        os.makedirs(results_folder)

        with zipfile.ZipFile(results_zip_file_path, 'r') as zip_file:
            zip_file.extractall(results_folder)

    def get_coverage_by_strategy(self, strategy: str):
        """
        returns the coverage by strategy name
        """
        results_folder = os.path.join(self._config.temp_folder, self._config.results_dir)
        strategy_result_folder = os.path.join(results_folder, f"{strategy}_fuzzing")

        coverage_by_contract_name = {}
        executions_by_contract_name = {}
        for path in os.listdir(strategy_result_folder):
            with open(os.path.join(strategy_result_folder, path), 'r') as file:
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
                            coverage_by_contract_name[contract_name] += execution["execution"]["coverage"] / execution["execution"]["totalInstructions"]
                            executions_by_contract_name[contract_name] += 1

        for contract_name in coverage_by_contract_name.keys():
            if executions_by_contract_name[contract_name] == 0:
                coverage_by_contract_name[contract_name] = -1
                continue
            coverage_by_contract_name[contract_name] = coverage_by_contract_name[contract_name] / executions_by_contract_name[contract_name]

        return coverage_by_contract_name





