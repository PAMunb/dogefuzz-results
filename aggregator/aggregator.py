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

        self._print_coverage_result()
        # print(f"read {len(contracts)} contracts:")
        # for element in contracts:
        #     print(element)

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
        print("| {0:35} | {1:20} | {2:20} | {3:20} |".format("TOTAL", "", "{0:.2f}%".format(greybox_diff_total), "{0:.2f}%".format(directed_greybox_diff_total)))
        print('-' * 108)
