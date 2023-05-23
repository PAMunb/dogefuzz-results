from aggregator.services.contract import ContractService
from aggregator.services.input import InputService
from aggregator.services.output import OutputService
from aggregator.services.result import ResultService


class Aggregator():

    def __init__(self) -> None:
        self._input_service = InputService()
        self._contract_service = ContractService()
        self._result_service = ResultService()
        self._output_service = OutputService()

    def generate_report(self, results_folder: str):
        self._input_service.extract_inputs()
        contracts = self._contract_service.list_contracts_from_contract_list()
        self._result_service.extract_results(results_folder)
        self._output_service.write_report(results_folder, contracts)
