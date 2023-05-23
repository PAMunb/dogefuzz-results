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
        results_folder = os.path.join(self._config.results_folder, results_folder_name)
        output_file_path = os.path.join(results_folder, "output.txt")

        if os.path.exists(output_file_path):
            os.remove(output_file_path)

        with open(output_file_path, "wt", encoding="utf-8") as f:
            self._write_coverage_result(f)
            self._write_critial_instructions_hits(f)
            self._write_vulnerabilities(contracts, f, False)

    def _write_coverage_result(self, file):
        self._write_line(file, 'COVERAGE RESULTS')
        coverage_for_blackbox = self._result_service.get_coverage_by_strategy(BLACKBOX_FUZZING)
        coverage_for_greybox = self._result_service.get_coverage_by_strategy(GREYBOX_FUZZING)
        coverage_for_directed_greybox = self._result_service.get_coverage_by_strategy(DIRECTED_GREYBOX_FUZZING)
        self._write_line(file, '-' * 108)
        self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format("contract_name", "blackbox", "greybox", "directed_greybox"))
        self._write_line(file, '-' * 108)

        greybox_diff_total = 0
        directed_greybox_diff_total = 0
        for contract_name in coverage_for_blackbox.keys():
            percentage_blackbox = "{0:.2f}%".format(coverage_for_blackbox[contract_name] * 100) if coverage_for_blackbox[contract_name] != -1 else "N/A"

            greybox_diff = coverage_for_greybox[contract_name] - coverage_for_blackbox[contract_name]
            greybox_diff_total += greybox_diff
            percentage_greybox = "{0:.2f}% ({1}{2:.2f}%)".format(coverage_for_greybox[contract_name] * 100, "+" if greybox_diff > 0 else "", greybox_diff * 100) if coverage_for_greybox[contract_name] != -1 else "N/A"

            directed_greybox_diff = coverage_for_directed_greybox[contract_name] - coverage_for_blackbox[contract_name]
            directed_greybox_diff_total += directed_greybox_diff
            percentage_directed_greybox = "{0:.2f}% ({1}{2:.2f}%)".format(coverage_for_directed_greybox[contract_name] * 100, "+" if directed_greybox_diff > 0 else "", directed_greybox_diff * 100) if coverage_for_directed_greybox[contract_name] != -1 else "N/A"

            self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format(contract_name, percentage_blackbox, percentage_greybox, percentage_directed_greybox))

        self._write_line(file, '-' * 108)
        self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format("AVERAGE", "", "{0}{1:.2f}%".format("+" if greybox_diff_total > 0 else "", (greybox_diff_total) * 100 / len(coverage_for_blackbox.keys())), "{0}{1:.2f}%".format("+" if directed_greybox_diff_total > 0 else "", (directed_greybox_diff_total) * 100 / len(coverage_for_blackbox.keys()))))
        self._write_line(file, '-' * 108)

    def _write_critial_instructions_hits(self, file):
        self._write_line(file, '\nCRITICAL INSTRUCTIONS HITS RESULTS')
        hits_for_blackbox = self._result_service.get_hits_by_strategy(BLACKBOX_FUZZING)
        hits_for_greybox = self._result_service.get_hits_by_strategy(GREYBOX_FUZZING)
        hits_for_directed_greybox = self._result_service.get_hits_by_strategy(DIRECTED_GREYBOX_FUZZING)
        self._write_line(file, '-' * 108)
        self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format("contract_name", "blackbox", "greybox", "directed_greybox"))
        self._write_line(file, '-' * 108)

        greybox_diff_total = 0
        directed_greybox_diff_total = 0
        for contract_name in hits_for_blackbox.keys():
            percentage_blackbox = "{0:.0f}".format(hits_for_blackbox[contract_name]) if hits_for_blackbox[contract_name] != -1 else "N/A"

            greybox_diff = ((hits_for_greybox[contract_name] - hits_for_blackbox[contract_name]) / hits_for_blackbox[contract_name]) if hits_for_blackbox[contract_name] != 0 else hits_for_greybox[contract_name]
            greybox_diff_total += greybox_diff
            percentage_greybox = "{0:.0f} ({1}{2:.2f}%)".format(hits_for_greybox[contract_name], "+" if greybox_diff > 0 else "", greybox_diff * 100) if hits_for_greybox[contract_name] != -1 else "N/A"

            directed_greybox_diff = ((hits_for_directed_greybox[contract_name] - hits_for_blackbox[contract_name]) / hits_for_blackbox[contract_name]) if hits_for_blackbox[contract_name] != 0 else hits_for_directed_greybox[contract_name]
            directed_greybox_diff_total += directed_greybox_diff
            percentage_directed_greybox = "{0:.0f} ({1}{2:.2f}%)".format(hits_for_directed_greybox[contract_name], "+" if directed_greybox_diff > 0 else "", directed_greybox_diff * 100) if hits_for_directed_greybox[contract_name] != -1 else "N/A"

            self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format(contract_name, percentage_blackbox, percentage_greybox, percentage_directed_greybox))

        self._write_line(file, '-' * 108)
        self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format("AVERAGE", "", "{0}{1:.2f}%".format("+" if greybox_diff_total > 0 else "", greybox_diff_total * 100 / len(hits_for_blackbox.keys())), "{0}{1:.2f}%".format("+" if directed_greybox_diff_total > 0 else "", directed_greybox_diff_total * 100 / len(hits_for_blackbox.keys()))))
        self._write_line(file, '-' * 108)

    def _write_vulnerabilities(self, contracts: list, file, include_new_detections: bool = True):
        self._write_line(file, '\nVULNERABILITIES RESULTS')
        vulnerability_types = [
            "delegate",
            "exception-disorder",
            "gasless-send",
            "number-dependency",
            "reentrancy",
            "timestamp-dependency",
        ]
        detection_rate_for_blackbox = self._result_service.get_detection_rate_by_strategy(BLACKBOX_FUZZING, contracts, vulnerability_types, include_new_detections)
        detection_rate_for_greybox = self._result_service.get_detection_rate_by_strategy(GREYBOX_FUZZING, contracts, vulnerability_types, include_new_detections)
        detection_rate_for_directed_greybox = self._result_service.get_detection_rate_by_strategy(DIRECTED_GREYBOX_FUZZING, contracts, vulnerability_types, include_new_detections)

        self._write_line(file, '-' * 108)
        self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format("contract_name", "blackbox", "greybox", "directed_greybox"))
        self._write_line(file, '-' * 108)

        greybox_diff_total = 0
        directed_greybox_diff_total = 0
        for vulnerability in vulnerability_types:
            percentage_blackbox = "{0:.2f}%".format(detection_rate_for_blackbox[vulnerability] * 100) if detection_rate_for_blackbox[vulnerability] != -1 else "N/A"

            greybox_diff = ((detection_rate_for_greybox[vulnerability] - detection_rate_for_blackbox[vulnerability]) / detection_rate_for_blackbox[vulnerability]) if detection_rate_for_blackbox[vulnerability] != 0 else detection_rate_for_greybox[vulnerability]
            greybox_diff_total += greybox_diff
            percentage_greybox = "{0:.2f}% ({1}{2:.2f}%)".format(detection_rate_for_greybox[vulnerability] * 100,  '+' if greybox_diff > 0 else '', greybox_diff * 100) if detection_rate_for_greybox[vulnerability] != -1 else "N/A"

            directed_greybox_diff = ((detection_rate_for_directed_greybox[vulnerability] - detection_rate_for_blackbox[vulnerability]) / detection_rate_for_blackbox[vulnerability]) if detection_rate_for_blackbox[vulnerability] != 0 else detection_rate_for_directed_greybox[vulnerability]
            directed_greybox_diff_total += directed_greybox_diff
            percentage_directed_greybox = "{0:.2f}% ({1}{2:.2f}%)".format(detection_rate_for_directed_greybox[vulnerability] * 100, '+' if directed_greybox_diff > 0 else '', directed_greybox_diff * 100) if detection_rate_for_directed_greybox[vulnerability] != -1 else "N/A"

            self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format(vulnerability, percentage_blackbox, percentage_greybox, percentage_directed_greybox))

        self._write_line(file, '-' * 108)
        self._write_line(file, "| {0:35} | {1:20} | {2:20} | {3:20} |".format("AVERAGE", "", "+{0:.2f}%".format(greybox_diff_total * 100 / len(detection_rate_for_blackbox.keys())), "+{0:.2f}%".format(directed_greybox_diff_total * 100 / len(detection_rate_for_blackbox.keys()))))
        self._write_line(file, '-' * 108)

    def _write_line(self, file, line: str):
        file.write(line + '\n')
