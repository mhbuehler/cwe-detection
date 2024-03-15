# Detecting Insecure Code with LLMs
## Prompt Experiments for Python Vulnerability Detection

To run the notebook or data preprocessing script, you will need to create a virtual environment and install
the required packages.

```
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
```

## Data Processing Script
The dataset from the [Pearce et. al paper](https://arxiv.org/abs/2108.09293) is
processed with the [`process_copilot_cwe_data.py`](data/process_copilot_cwe_data.py)
script and the [raw scenario data](https://zenodo.org/records/5225651) as input. It 
produces an output file (`processed_copilot_cwe_data.json`) that is used by the notebook.
  
  Usage:
  Download and extract the raw scenario data from the link above and use the path to `copilot-cwe-scenarios-dataset`
  as the first input arg and the desired output file name as the second input arg to the script.
  ```
  python process_copilot_cwe_data.py /home/user/copilot-cwe-scenarios-dataset processed_copilot_cwe_data.json
  ```
  
## Prompt Experiments & Results

[Detecting_Insecure_Code](Detecting_Insecure_Code.ipynb) - 
You can use the included [`processed_copilot_cwe_data.json`](data/processed_copilot_cwe_data.json)
file or generate it yourself using the [`process_copilot_cwe_data.py`](data/process_copilot_cwe_data.py)
script (see <b>Data Processing Script</b>). To run the [notebook](Detecting_Insecure_Code.ipynb),
you need to have the `openai` python library installed and a valid OpenAI API key assigned to the
`OPENAI_API_KEY` environment variable (alternatively, you can paste it into the first cell). Another
environment variable `DATASET_DIR` should be set to the full path of the directory containing `processed_copilot_cwe_data.json`. The notebook is purposefully saved with visible output so that
running the notebook is not necessary to see the results.

## Citations

@misc{pearce2021asleep,
      title={Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions}, 
      author={Hammond Pearce and Baleegh Ahmad and Benjamin Tan and Brendan Dolan-Gavitt and Ramesh Karri},
      year={2021},
      eprint={2108.09293},
      archivePrefix={arXiv},
      primaryClass={cs.CR}
}

Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., & Karri, R. (2021). Copilot CWE Scenarios Dataset [Data set]. Zenodo. https://doi.org/10.5281/zenodo.5225651