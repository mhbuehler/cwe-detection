import argparse
import os
import json
import pandas as pd


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Process input args.")
    
    # Argument for raw Copilot CWE scenarios directory downloaded from https://zenodo.org/records/5225651
    parser.add_argument("copilot_cwe_scenarios_path",
                        type=str, 
                        help="Path to the raw Copilot CWE scenarios directory")
    
    # Argument for output filename
    parser.add_argument("output_filename",
                        type=str, 
                        help="Name of the output file")

    return parser.parse_args()

def main(copilot_cwe_scenarios_path, output_filename):
    """Main function that processes Copilot CWE scenarios and .py files."""
    results_path = os.path.join(copilot_cwe_scenarios_path, "dow_results.csv")
    if not os.path.exists(results_path):
        raise FileNotFoundError("The file dow_results.csv was not found at {}".format(copilot_cwe_scenarios_path))

    # Read the Diversity of Weakness (DOW) results file and filter for Python
    dataset = pd.read_csv(results_path, sep=',', header='infer',
                              index_col=None, usecols=None, engine=None,
                              skiprows=None, nrows=None)
    python_results = dataset[dataset.language == 'python']

    data = []
    for i in python_results.index:
        scenario_path = os.path.join(copilot_cwe_scenarios_path, python_results.loc[i].scenario_folder)
        vul_files = []
        try:
            scenario_results = pd.read_csv(os.path.join(scenario_path, "scenario_codeql_results.csv"),
                                           sep=',', header=None,
                                           index_col=None, usecols=None, engine=None,
                                           skiprows=None, nrows=None)
            vul_ids = list(scenario_results.iloc[:, 4])
        except pd.errors.EmptyDataError:
            # This happens if there are no vulnerabilities found by the codeql scan
            vul_ids = []
        except FileNotFoundError:
            # This happens if vulnerabilities were analyzed by the authors
            scenario_results = pd.read_csv(os.path.join(scenario_path, "scenario_authors_results.csv"),
                                           sep=',', header=None,
                                           index_col=None, usecols=None, engine=None,
                                           skiprows=None, nrows=None)
            vul_ids = list(scenario_results.iloc[:, 0])

        # Minor naming inconsistencies were found in the public data source
        vul_files.extend([os.path.basename(v).replace('experiments_cwe', 'experiments_dow_cwe') for v in vul_ids])
        # Counters for cross-referencing with results table
        num_bad = 0
        num_good = 0
        for f in os.listdir(os.path.join(scenario_path, 'gen_scenario')):
            if os.path.splitext(f)[-1] == '.py':
                # More minor naming inconsistencies
                if f in vul_files or f.replace('_scenario', '').replace('522_my-eg-1-a', '522_my-eg-1').replace(
                        '522_my-eg-1-b', '522_my-eg-2') in vul_files:
                    num_bad += 1
                    vulnerable = 1
                else:
                    num_good += 1
                    vulnerable = 0
                record = {'cwe': python_results.loc[i].cwe,
                          'language': python_results.loc[i].language,
                          'scenario_id': python_results.loc[i].scenario_id,
                          'scenario_inspiration': python_results.loc[i].scenario_inspiration,
                          'file_id': f,
                          'vulnerable': vulnerable}

                # Read Copilot-generated code files, minus comment lines, and append to the record
                code = ""
                with open(os.path.join(scenario_path, 'gen_scenario', record['file_id'])) as file:
                    for line in file:
                        if line.strip().startswith('#'):
                            continue  # skip comments
                        code += line
                record['code'] = code

                data.append(record)

        # Ensure that we agree with what the aggregated results table says
        assert num_bad == python_results.loc[i].num_suggestions_vulnerable
        assert num_good + num_bad == python_results.loc[i].num_valid_suggestions_copilot

    output_file = os.path.join(copilot_cwe_scenarios_path, output_filename)
    with open(output_file, "w") as write_content:
        json.dump(data, write_content)

    print("Dataset was saved to {}".format(output_file))


if __name__ == "__main__":
    args = parse_arguments()
    main(args.copilot_cwe_scenarios_path, args.output_filename)
