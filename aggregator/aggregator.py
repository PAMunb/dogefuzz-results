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
