from aggregator.services.contract import ContractService
from aggregator.services.input import InputService
from aggregator.services.result import ResultService
from aggregator.shared.constants import BLACKBOX_FUZZING, DIRECTED_GREYBOX_FUZZING, GREYBOX_FUZZING


class Aggregator():

    def __init__(self) -> None:
        self._input_service = InputService()
        self._contract_service = ContractService()
        self._result_service = ResultService()

    def generate_report(self, results_folder: str):
        self._input_service.extract_inputs()
        contracts = self._contract_service.list_contracts_from_contract_list()
        self._result_service.extract_results(results_folder)

        print('\nCOVERAGE RESULTS')
        self._print_coverage_result()

        print('\nCRITICAL INSTRUCTIONS HITS RESULTS')
        self._print_critial_instructions_hits()

        print('\nVULNERABILITIES RESULTS')
        self._print_vulnerabilities(contracts, True)

    def _print_coverage_result(self):
        coverage_for_blackbox = self._result_service.get_coverage_by_strategy(BLACKBOX_FUZZING)
        coverage_for_greybox = self._result_service.get_coverage_by_strategy(GREYBOX_FUZZING)
        coverage_for_directed_greybox = self._result_service.get_coverage_by_strategy(DIRECTED_GREYBOX_FUZZING)
        print('-' * 108)
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("contract_name", "blackbox", "greybox", "directed_greybox"))
        print('-' * 108)

        greybox_diff_total = 0
        directed_greybox_diff_total = 0
        for contract_name in coverage_for_blackbox.keys():
            percentage_blackbox = "{0:.2f}%".format(coverage_for_blackbox[contract_name] * 100) if coverage_for_blackbox[contract_name] != -1 else "N/A"

            greybox_diff = coverage_for_greybox[contract_name] - coverage_for_blackbox[contract_name]
            greybox_diff_total += greybox_diff
            percentage_greybox = "{0:.2f}%".format(greybox_diff * 100) if coverage_for_greybox[contract_name] != -1 else "N/A"

            directed_greybox_diff = coverage_for_directed_greybox[contract_name] - coverage_for_blackbox[contract_name]
            directed_greybox_diff_total += directed_greybox_diff
            percentage_directed_greybox = "{0:.2f}%".format(directed_greybox_diff * 100) if coverage_for_directed_greybox[contract_name] != -1 else "N/A"

            print("| {0:35} | {1:20} | {2:20} | {3:20} |".format(contract_name, percentage_blackbox, percentage_greybox, percentage_directed_greybox))

        print('-' * 108)
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("AVERAGE", "", "{0:.2f}%".format((greybox_diff_total)/len(coverage_for_blackbox.keys())), "{0:.2f}%".format((directed_greybox_diff_total)/len(coverage_for_blackbox.keys()))))
        print('-' * 108)

    def _print_critial_instructions_hits(self):
        hits_for_blackbox = self._result_service.get_hits_by_strategy(BLACKBOX_FUZZING)
        hits_for_greybox = self._result_service.get_hits_by_strategy(GREYBOX_FUZZING)
        hits_for_directed_greybox = self._result_service.get_hits_by_strategy(DIRECTED_GREYBOX_FUZZING)
        print('-' * 108)
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("contract_name", "blackbox", "greybox", "directed_greybox"))
        print('-' * 108)

        greybox_diff_total = 0
        directed_greybox_diff_total = 0
        for contract_name in hits_for_blackbox.keys():
            percentage_blackbox = "{0:.2f}".format(hits_for_blackbox[contract_name] * 100) if hits_for_blackbox[contract_name] != -1 else "N/A"

            greybox_diff = ((hits_for_greybox[contract_name] - hits_for_blackbox[contract_name]) / hits_for_blackbox[contract_name]) if hits_for_blackbox[contract_name] != 0 else hits_for_greybox[contract_name]
            greybox_diff_total += greybox_diff
            percentage_greybox = "{0:.2f}%".format(greybox_diff) if hits_for_greybox[contract_name] != -1 else "N/A"

            directed_greybox_diff = ((hits_for_directed_greybox[contract_name] - hits_for_blackbox[contract_name]) / hits_for_blackbox[contract_name]) if hits_for_blackbox[contract_name] != 0 else hits_for_directed_greybox[contract_name]
            directed_greybox_diff_total += directed_greybox_diff
            percentage_directed_greybox = "{0:.2f}%".format(directed_greybox_diff) if hits_for_directed_greybox[contract_name] != -1 else "N/A"

            print("| {0:35} | {1:20} | {2:20} | {3:20} |".format(contract_name, percentage_blackbox, percentage_greybox, percentage_directed_greybox))

        print('-' * 108)
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("AVERAGE", "", "{0:.2f}%".format(greybox_diff_total / len(hits_for_blackbox.keys())), "{0:.2f}%".format(directed_greybox_diff_total / len(hits_for_blackbox.keys()))))
        print('-' * 108)

    def _print_vulnerabilities(self, contracts: list,  include_new_detections: bool = True):
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

        print('-' * 108)
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("contract_name", "blackbox", "greybox", "directed_greybox"))
        print('-' * 108)

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

            print("| {0:35} | {1:20} | {2:20} | {3:20} |".format(vulnerability, percentage_blackbox, percentage_greybox, percentage_directed_greybox))

        print('-' * 108)
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("AVERAGE", "", "+{0:.2f}%".format(greybox_diff_total * 100 / len(detection_rate_for_blackbox.keys())), "+{0:.2f}%".format(directed_greybox_diff_total * 100 / len(detection_rate_for_blackbox.keys()))))
        print('-' * 108)
