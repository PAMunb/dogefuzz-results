import os
import json
import numpy as np

from matplotlib import pyplot as plt
from sklearn.cluster import KMeans


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
        contracts = self._contract_service.list_contracts_from_contract_list(False)
        self._result_service.extract_results(results_folder)
        self._output_service.write_report(results_folder, contracts, False)

    def generate_report_smartian(self, results_folder: str):
        self._input_service.extract_inputs()
        contracts = self._contract_service.list_contracts_from_contract_list(True)
        self._result_service.extract_results(results_folder)
        self._result_service.convert_results_to_smartian(results_folder)
        self._output_service.write_report(results_folder, contracts, True)

    def show_kmeans(self, cluster_number: int = 3):
        inputs_file = os.path.join(os.path.dirname(
            __file__), '..', 'resources', 'inputs.json')

        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            dataset = np.array([[input['numberOfBranches'], sum(
                input['numberOfCriticalInstructions'].values())] for input in inputs])

            kmeans = KMeans(n_clusters=cluster_number, init='random',
                            n_init=10, max_iter=100)
            kmeans.fit(dataset)

            plt.scatter(dataset[:, 0], dataset[:, 1], c=kmeans.labels_)
            plt.title('Clusterização dos Contratos')
            plt.xlabel('Número de Arestas')
            plt.xlim(-50, 450)
            plt.ylabel('Número de Instruções Críticas')
            plt.ylim(-5, 20)
            plt.grid()
            plt.show()

    def show_elbow_method(self):
        inputs_file = os.path.join(os.path.dirname(
            __file__), '..', 'resources', 'inputs.json')

        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            dataset = np.array([[input['numberOfBranches'], sum(
                input['numberOfCriticalInstructions'].values())] for input in inputs])

            inertias = []

            for i in range(1, 11):
                kmeans = KMeans(n_clusters=i, n_init=10)
                kmeans.fit(dataset)
                inertias.append(kmeans.inertia_)

            plt.plot(range(1, 11), inertias, marker='o')
            plt.title('Método Elbow')
            plt.xlabel('Número de Clusters')
            plt.ylabel('Inercia')
            plt.show()

    def inputs_stats_smartian(self):
        self._input_service.extract_inputs()
        contracts = self._contract_service.list_contracts_from_contract_list(True)
        self._print_all(contracts)
        
    def inputs_stats(self):
        self._input_service.extract_inputs()
        contracts = self._contract_service.list_contracts_from_contract_list(False)

        self._print_all(contracts)

    def _print_all(self, contracts):
        vulnerabilities = {}
        for contract in contracts:
            for vulnerability in contract['vulnerabilities']:
                vulnerabilities[vulnerability] = vulnerabilities.get(
                    vulnerability, 0) + 1
        inputs_file = os.path.join(os.path.dirname(
            __file__), '..', 'resources', 'inputs.json')

        clusters = {}
        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            dataset = np.array([[input['numberOfBranches'], sum(
                input['numberOfCriticalInstructions'].values())] for input in inputs])
            kmeans = KMeans(n_clusters=3, init='random',
                            n_init=10, max_iter=100)
            kmeans.fit(dataset)

            letters = ['A', 'B', 'C']
            for i in kmeans.labels_:
                clusters[letters[i]] = clusters.get(letters[i], 0) + 1

        print(f'Número de contratos: {len(contracts)}')
        print("------------------------------")
        print("Contratos por Vulnerabilidade:")
        for vulnerability, count in vulnerabilities.items():
            print(f'{vulnerability:20}: {count:5}')

        print("------------------------------")
        print("Contratos por Cluster:")
        for cluster, count in clusters.items():
            print(f'Cluster {cluster:1}: {count:5}')

    def show_correlation(self):
        delegate_data = [
            [26.67, 12.53, 0.75, 1],
            [26.67, 12.32, 0.76, 1],
            [33.33, 12.41, 0.80, 1],
            [40.00, 12.29, 0.82, 5],
            [46.67, 12.81, 0.82, 5],
            [33.33, 13.04, 0.91, 5],
            [40.00, 12.59, 0.77, 10],
            [46.67, 12.30, 0.70, 10],
            [53.33, 13.32, 0.84, 10],
        ]

        delegate_correlation = np.corrcoef(delegate_data, rowvar=False)
        print()
        print("Delegate Correlation Matrix")
        print("------------------------------")
        print(delegate_correlation)

        exception_disorder_data = [
            [37.50, 13.67, 1.66, 1],
            [33.33, 13.95, 1.82, 1],
            [41.67, 14.51, 1.71, 1],
            [58.33, 13.95, 1.61, 5],
            [58.33, 14.33, 1.72, 5],
            [54.17, 14.47, 1.65, 5],
            [58.33, 14.26, 1.67, 10],
            [66.67, 13.73, 1.69, 10],
            [62.50, 14.11, 1.67, 10],
        ]

        exception_disorder_correlation = np.corrcoef(
            exception_disorder_data, rowvar=False)
        print()
        print("Exception Disorder Correlation Matrix")
        print("------------------------------")
        print(exception_disorder_correlation)

        gasless_send_data = [
            [61.54, 10.63, 1.16, 1],
            [53.85, 10.84, 1.03, 1],
            [69.23, 10.62, 1.05, 1],
            [61.54, 10.69, 1.05, 5],
            [61.54, 10.77, 1.11, 5],
            [61.54, 10.98, 1.09, 5],
            [61.54, 10.82, 1.09, 10],
            [61.54, 10.82, 1.09, 10],
            [61.54, 10.86, 1.09, 10]
        ]

        gasless_send_correlation = np.corrcoef(
            gasless_send_data, rowvar=False)
        print()
        print("Gassless Send Correlation Matrix")
        print("------------------------------")
        print(gasless_send_correlation)

        number_dependency_data = [
            [5.63, 11.38, 3.34, 1],
            [8.45, 11.42, 3.66, 1],
            [9.86, 11.35, 3.19, 1],
            [7.04, 11.71, 3.55, 5],
            [11.27, 11.71, 3.61, 5],
            [11.27, 11.72, 3.48, 5],
            [7.04, 11.73, 3.31, 10],
            [11.27, 11.70, 3.50, 10],
            [11.27, 11.64, 3.44, 10]
        ]

        number_dependency_correlation = np.corrcoef(
            number_dependency_data, rowvar=False)
        print()
        print("Number Dependency Correlation Matrix")
        print("------------------------------")
        print(number_dependency_correlation)

        timestamp_dependency_data = [
            [10.91, 9.85, 3.94, 1],
            [17.27, 9.77, 3.95, 1],
            [13.64, 9.93, 3.58, 1],
            [12.73, 10.00, 3.90, 5],
            [18.18, 10.11, 4.07, 5],
            [17.27, 10.12, 3.83, 5],
            [16.36, 10.09, 3.92, 10],
            [21.82, 10.07, 3.81, 10],
            [19.09, 10.13, 3.96, 10]
        ]

        timestamp_dependency_correlation = np.corrcoef(
            timestamp_dependency_data, rowvar=False)
        print()
        print("Timestamp Dependency Correlation Matrix")
        print("------------------------------")
        print(timestamp_dependency_correlation)

        reentrancy_data = [
            [0.1, 13.92, 0.88, 1],
            [0.1, 13.90, 1.06, 1],
            [0.1, 13.39, 1.00, 1],
            [0.1, 14.53, 1.06, 5],
            [0.1, 14.13, 1.15, 5],
            [0.1, 14.12, 1.10, 5],
            [0.1, 14.42, 1.06, 10],
            [0.1, 14.02, 1.11, 10],
            [0.1, 13.91, 1.26, 10]
        ]

        reentrancy_correlation = np.corrcoef(
            reentrancy_data, rowvar=False)
        print()
        print("Reentrancy Correlation Matrix")
        print("------------------------------")
        print(reentrancy_correlation)
