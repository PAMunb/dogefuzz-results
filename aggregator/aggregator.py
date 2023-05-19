from aggregator.services.contract import ContractService
from aggregator.services.drive import DriveService


class Aggregator():

    def __init__(self) -> None:
        self._drive_service = DriveService()
        self._contract_service = ContractService()

    def generate_report(self, results_folder: str):
        self._drive_service.download_contracts()
        contracts = self._contract_service.list_contracts_from_contract_list()
        print(f"read {len(contracts)} contracts:")
        for element in contracts:
            print(element)
