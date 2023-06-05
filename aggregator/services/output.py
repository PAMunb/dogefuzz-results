import os
from aggregator.config import Config

from aggregator.services.result import ResultService
from aggregator.shared.constants import BLACKBOX_FUZZING, DIRECTED_GREYBOX_FUZZING, GREYBOX_FUZZING
from aggregator.shared.singleton import SingletonMeta


class OutputService(metaclass=SingletonMeta):

    def __init__(self) -> None:
        self._config = Config()
        self._result_service = ResultService()

    def write_report(self, results_folder_name: str, contracts: list):
        """
        writes the output to the output file
        """
        results_folder = os.path.join(
            self._config.results_folder, results_folder_name)
        output_file_path = os.path.join(results_folder, "output.txt")

        if os.path.exists(output_file_path):
            os.remove(output_file_path)

        with open(output_file_path, "wt", encoding="utf-8") as f:
            self._write_max_coverage_result(f)
            self._write_average_coverage_result(f)
            self._write_critial_instructions_hits(f)
            self._write_vulnerabilities(contracts, f, False)

    def _write_max_coverage_result(self, file):
        (max_coverage_per_contract_for_blackbox, average_coverage_for_blackbox) = self._result_service.get_max_coverage_by_strategy(
            BLACKBOX_FUZZING)
        (max_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_max_coverage_by_strategy(
            GREYBOX_FUZZING)
        (max_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_max_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING)

        self._write_header(file, 'MAX COVERAGE RESULTS')

        for contract_name in max_coverage_per_contract_for_blackbox:
            blackbox = max_coverage_per_contract_for_blackbox[contract_name]
            greybox = max_coverage_per_contract_for_greybox[contract_name]
            directed_greybox = max_coverage_per_contract_for_directed_greybox[
                contract_name]

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:35} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")

        self._write_average_footer(file, average_coverage_for_blackbox,
                                   average_coverage_for_greybox, average_coverage_for_directed_greybox)

    def _write_average_coverage_result(self, file):
        (average_coverage_per_contract_for_blackbox, average_converage_for_blackbox) = self._result_service.get_average_coverage_by_strategy(
            BLACKBOX_FUZZING)
        (average_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_average_coverage_by_strategy(
            GREYBOX_FUZZING)
        (average_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_average_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING)

        self._write_header(file, 'AVERAGE COVERAGE RESULTS')

        for contract_name in average_coverage_per_contract_for_blackbox:
            blackbox = average_coverage_per_contract_for_blackbox[contract_name]
            greybox = average_coverage_per_contract_for_greybox[contract_name]
            directed_greybox = average_coverage_per_contract_for_directed_greybox[
                contract_name]

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:35} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")

        self._write_average_footer(file, average_converage_for_blackbox,
                                   average_coverage_for_greybox, average_coverage_for_directed_greybox)

    def _write_critial_instructions_hits(self, file):
        (hits_per_contract_for_blackbox, average_hits_for_blackbox) = self._result_service.get_hits_by_strategy(
            BLACKBOX_FUZZING)
        (hits_per_contract_for_greybox, average_hits_for_greybox) = self._result_service.get_hits_by_strategy(
            GREYBOX_FUZZING)
        (hits_per_contract_for_directed_greybox, average_hits_for_directed_greybox) = self._result_service.get_hits_by_strategy(
            DIRECTED_GREYBOX_FUZZING)

        self._write_header(file, 'CRITICAL INSTRUCTIONS HITS RESULTS')

        for contract_name in hits_per_contract_for_blackbox:
            blackbox = hits_per_contract_for_blackbox[contract_name]
            greybox = hits_per_contract_for_greybox[contract_name]
            directed_greybox = hits_per_contract_for_directed_greybox[contract_name]

            hits_for_blackbox = self._convert_to_str(blackbox)
            hits_for_greybox = self._convert_to_diff_str(greybox, blackbox)
            hits_for_directed_greybox = self._convert_to_diff_str(
                directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:35} | {hits_for_blackbox:20} | {hits_for_greybox:20} | {hits_for_directed_greybox:20} |")
        self._write_average_number_footer(file, average_hits_for_blackbox,
                                          average_hits_for_greybox, average_hits_for_directed_greybox)

    def _write_vulnerabilities(self, contracts: list, file, include_new_detections: bool = True):
        vulnerability_types = [
            "delegate",
            "exception-disorder",
            "gasless-send",
            "number-dependency",
            "reentrancy",
            "timestamp-dependency",
        ]
        detection_rate_for_blackbox = self._result_service.get_detection_rate_by_strategy(
            BLACKBOX_FUZZING, contracts, vulnerability_types, include_new_detections)
        detection_rate_for_greybox = self._result_service.get_detection_rate_by_strategy(
            GREYBOX_FUZZING, contracts, vulnerability_types, include_new_detections)
        detection_rate_for_directed_greybox = self._result_service.get_detection_rate_by_strategy(
            DIRECTED_GREYBOX_FUZZING, contracts, vulnerability_types, include_new_detections)

        self._write_header(file, 'VULNERABILITIES RESULTS')

        average_detection_rate_for_blackbox = 0
        average_detection_rate_for_greybox = 0
        average_detection_rate_for_directed_greybox = 0
        for vulnerability in vulnerability_types:
            blackbox = detection_rate_for_blackbox[vulnerability]
            greybox = detection_rate_for_greybox[vulnerability]
            directed_greybox = detection_rate_for_directed_greybox[vulnerability]

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            average_detection_rate_for_blackbox += blackbox
            average_detection_rate_for_greybox += greybox
            average_detection_rate_for_directed_greybox += directed_greybox

            self._write_line(
                file, f"| {vulnerability:35} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")

        average_blackbox = average_detection_rate_for_blackbox / \
            len(vulnerability_types)
        average_greybox = average_detection_rate_for_greybox / \
            len(vulnerability_types)
        average_directed_greybox = average_detection_rate_for_directed_greybox / \
            len(vulnerability_types)

        self._write_average_footer(
            file, average_blackbox, average_greybox, average_directed_greybox)

    def _write_header(self, file, title: str):
        self._write_line(file, "\n")
        self._write_line(file, title)
        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'contract_name':35} | {'blackbox':20} | {'greybox':20} | {'directed_greybox':20} |")
        self._write_dashed_line(file)

    def _write_average_footer(self, file, average_blackbox, average_greybox, average_directed_greybox):
        percentage_blackbox = self._convert_to_percentage_str(average_blackbox)
        percentage_greybox = self._convert_to_percentage_diff_str(
            average_greybox, average_blackbox)
        percentage_directed_greybox = self._convert_to_percentage_diff_str(
            average_directed_greybox, average_blackbox)

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'AVERAGE':35} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _write_average_number_footer(self, file, average_blackbox, average_greybox, average_directed_greybox):
        number_blackbox = self._convert_to_str(average_blackbox)
        number_greybox = self._convert_to_diff_str(
            average_greybox, average_blackbox)
        number_directed_greybox = self._convert_to_diff_str(
            average_directed_greybox, average_blackbox)

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'AVERAGE':35} | {number_blackbox:20} | {number_greybox:20} | {number_directed_greybox:20} |")
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

    def _write_dashed_line(self, file):
        self._write_line(file, '-' * 108)

    def _write_line(self, file, line: str):
        file.write(line + '\n')
