import csv
import os

from aggregator.config import Config
from aggregator.shared.exceptions import ContractsNotFoundException
from aggregator.shared.singleton import SingletonMeta
from aggregator.shared.util import map_vulnerability_to_dogefuzz_standard

NAME_COLUMN = 0
VULNERABILITIES_COLUMN = 1
LINK_COLUMN = 2


class ContractService(metaclass=SingletonMeta):
    """sertice that contains operations with the available contracts
    """

    def __init__(self) -> None:
        self._config = Config()

    def list_contracts_from_contract_list(self) -> list:
        """lists the contracts from the contracts.csv file
        """
        if not os.path.exists(self._config.contracts_folder):
            raise ContractsNotFoundException(
                "the contracts were not downloaded yet. Please use the command download_contracts first")

        contracts = []
        contracts_csv = os.path.join(
            self._config.contracts_folder, "contracts.csv")
        with open(contracts_csv, 'r', encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                contract = {
                    "name": row[NAME_COLUMN],
                    "vulnerabilities": [x for x in [map_vulnerability_to_dogefuzz_standard(x) for x in row[VULNERABILITIES_COLUMN].split(";")] if x is not None],
                    "link": row[LINK_COLUMN],
                }
                contracts.append(contract)

        return contracts
