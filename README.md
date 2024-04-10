# Results Aggregator

This project will aggregate the result from [benchmark](https://github.com/pamunb/benchmark) project.

## Running the project locally

This project using Python 3.10 and [Poetry](https://python-poetry.org/) to manage its dependencies and virtual environment.


First, install Poetry:

```
curl -sSL https://install.python-poetry.org | python3 -
```

Second, install all dependdencies using poetry:

```
poetry install
```

To run the report generator, execute the following commands:

```
poetry run aggregator generate_report <experiment_folder>  <experiment_resource_zip>
```
It will look for a `experiment_folder` folder inside `/results` folder.

Available aggregator options are: 

```
generate_report_not_labeled - When you don't have a labeled dataset.
plot_max_coverage_boxplot -
plot_max_coverage_bar -
```


Available aggregator options for Smartian B2 benchmark experiment are: 

```
generate_report_smartian - For the dataset of 72 contracts from B2 benchmark of Smartian.
smartian_b2_alarms_avg - Generata a report for precision, recall and F1-score.
count_smartian_b2_bugs_found_avg - Sum the average of bugs detected.
count_smartian_b2_instruction_coverage_avg - Sum the code coverage  average.
plot_smartian_b2_bugs_found_avg - Generate a graph for average bugs found.
plot_smartian_b2_bugs_found - Generate a graph for total bugs found.
plot_smartian_b2_instruction_coverage - Generate a graph for code coverage.
plot_smartian_b2_instruction_coverage_avg - Generate a graph for average code coverage.

```
