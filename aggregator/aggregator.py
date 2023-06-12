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
        contracts = self._contract_service.list_contracts_from_contract_list()
        self._result_service.extract_results(results_folder)
        self._output_service.write_report(results_folder, contracts)

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

    def inputs_stats(self):
        self._input_service.extract_inputs()
        contracts = self._contract_service.list_contracts_from_contract_list()

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
            print(kmeans.labels_)
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
            [26.67, 11.77, 10.99, 1],
            [26.67, 11.75, 11.44, 1],
            [33.33, 11.85, 10.91, 1],
            [40.00, 12.03, 11.32, 5],
            [46.67, 12.14, 11.68, 5],
            [33.33, 12.18, 11.46, 5]
        ]

        delegate_correlation = np.corrcoef(delegate_data, rowvar=False)
        print()
        print("Delegate Correlation Matrix")
        print("------------------------------")
        print(delegate_correlation)

        exception_disorder_data = [
            [37.50, 11.77, 10.99, 1],
            [33.33, 11.75, 11.44, 1],
            [41.67, 11.85, 10.91, 1],
            [58.33, 12.03, 11.32, 5],
            [58.33, 12.14, 11.68, 5],
            [54.17, 12.18, 11.46, 5]
        ]

        exception_disorder_correlation = np.corrcoef(
            exception_disorder_data, rowvar=False)
        print()
        print("Exception Disorder Correlation Matrix")
        print("------------------------------")
        print(exception_disorder_correlation)

        gasless_send_data = [
            [61.54, 11.77, 10.99, 1],
            [53.85, 11.75, 11.44, 1],
            [69.23, 11.85, 10.91, 1],
            [61.54, 12.03, 11.32, 5],
            [61.54, 12.14, 11.68, 5],
            [61.54, 12.18, 11.46, 5]
        ]

        gasless_send_correlation = np.corrcoef(
            gasless_send_data, rowvar=False)
        print()
        print("Gassless Send Correlation Matrix")
        print("------------------------------")
        print(gasless_send_correlation)

        number_dependency_data = [
            [5.63, 11.77, 10.99, 1],
            [8.45, 11.75, 11.44, 1],
            [9.86, 11.85, 10.91, 1],
            [7.04, 12.03, 11.32, 5],
            [11.27, 12.14, 11.68, 5],
            [11.27, 12.18, 11.46, 5]
        ]

        number_dependency_correlation = np.corrcoef(
            number_dependency_data, rowvar=False)
        print()
        print("Number Dependency Correlation Matrix")
        print("------------------------------")
        print(number_dependency_correlation)

        timestamp_dependency_data = [
            [10.91, 11.77, 10.99, 1],
            [17.27, 11.75, 11.44, 1],
            [13.64, 11.85, 10.91, 1],
            [7.04, 12.03, 11.32, 5],
            [11.27, 12.14, 11.68, 5],
            [11.27, 12.18, 11.46, 5]
        ]

        timestamp_dependency_correlation = np.corrcoef(
            timestamp_dependency_data, rowvar=False)
        print()
        print("Timestamp Dependency Correlation Matrix")
        print("------------------------------")
        print(timestamp_dependency_correlation)

        reentrancy_data = [
            [0.1, 11.77, 10.99, 1],
            [0.1, 11.75, 11.44, 1],
            [0.1, 11.85, 10.91, 1],
            [0.1, 12.03, 11.32, 5],
            [0.1, 12.14, 11.68, 5],
            [0.1, 12.18, 11.46, 5]
        ]

        reentrancy_correlation = np.corrcoef(
            reentrancy_data, rowvar=False)
        print()
        print("Reentrancy Correlation Matrix")
        print("------------------------------")
        print(reentrancy_correlation)
