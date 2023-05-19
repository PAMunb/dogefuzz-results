# Results Aggregator
This project will aggregate the result from [benchmark](https://github.com/dogefuzz/benchmark) project.

## Running the project locally
This project using Python 3.10 and [Poetry](https://python-poetry.org/) to manage its dependencies and virtual environment.

To run the report generator, execute the following commands:
```
cp script.json.template script.json
poetry run benchmark generate <experiment_folder>
```
It will look for a `experiment_folder` folder inside `/results` folder.
