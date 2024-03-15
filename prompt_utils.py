import numpy as np
import openai
from rouge_score import rouge_scorer

def get_completion(prompt, model="gpt-4", temperature=0.6):
    messages = [{"role": "user", "content": prompt}]
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=temperature,
    )
    return response.choices[0].message["content"]

class PromptBase(object):
    """Base class for a prompt"""

    def __init__(self):
        self.template = """"""
        self.content_keys = []

    def get_prompt(self, content):
        assert content.keys() == set(self.content_keys)
        return self.template.format(**content)

      
class ZeroShotPrompt(PromptBase): 
    """A zero-shot prompt"""      
    def __init__(self, step_by_step=False, labels=False):
        super().__init__()
        self.step_by_step = step_by_step
        self.labels = labels
        self.template = \
        """You are a brilliant software security expert. """ \
        """\nYou will be provided with a python code delimited by triple backticks. """ \
        
        if labels:
            self.template += """\nIf it contains the security vulnerability {cwe}, write Vulnerable. """
        else:
            self.template += """\nIf it contains any CWE security vulnerabilities, write Vulnerable. """

        self.template += \
        """\nIf the code does not contain any vulnerabilities, write Not Vulnerable. """ \
        """\n\nPython code: ```{code}``` """ \
        """\n\nFormat your response as a JSON object with ”label” as the key """ \
        """\nfor vulnerability status and "cwe" as the vulnerability number found. """ 
        
        if step_by_step:
            self.template += """\nThink about the answer step by step, and only answer with JSON."""
        else:
            self.template += """\nOnly answer with JSON."""
        
        self.content_keys = ['code']
        if labels:
            self.content_keys.append('cwe')


class FewShotPrompt(PromptBase):  
    """A few-shot prompt"""     
    def __init__(self, step_by_step=False, n=3, fix=False, labels=False):
        super().__init__()
        self.step_by_step = step_by_step
        self.n = n
        self.fix = fix
        self.labels = labels
        self.template = \
        """You are a brilliant software security expert. """ \
        """\nYou will be provided with a python code delimited by triple backticks. """ \
        
        if labels:
            self.template += """\nIf it contains the security vulnerability {cwe}, write Vulnerable. """
        else:
            self.template += """\nIf it contains any CWE security vulnerabilities, write Vulnerable. """

        self.template += """\nIf the code does not contain any vulnerabilities, write Not Vulnerable. """ \
        
        if fix:
            self.template += """\nIf the code has the vulnerability, write a repaired secure version of the code that preserves its exact functionality. """

        self.template += """\nFormat your response as a JSON object with "label" as the key """ \
        
        if not fix:
            self.template += """\nfor vulnerability status and "cwe" as the vulnerability number found. """
        else:
            self.template += """\nfor vulnerability status, "cwe" as the vulnerability found, and "fix" for the fixed code snippet. """

        
        if step_by_step:
            self.template += """\nThink about the answer step by step, and only answer with JSON."""
        else:
            self.template += """\nOnly answer with JSON."""
        
        # Append n shots
        for i in range(n):
            self.template += """\n\nPython code: ```{{example_{0}}}```\n\nAnswer: {{answer_{0}}}""".format(str(i))
            self.content_keys.append('example_{}'.format(str(i)))
            self.content_keys.append('answer_{}'.format(str(i)))
        
        # Append the code
        self.template += """\n\nPython code: ```{code}```\n\nAnswer: """
        self.content_keys.append('code')
        if labels:
            self.content_keys.append('cwe')

        self.shots = []
        self.used_scenarios = []

    def _get_clean_example(self, scenario_id, df):
        """Get a non-vulnerable example from the df for the given scenario_id."""
        fixed = df.loc[[x for x in df.index if df.loc[x]['scenario_id']==scenario_id and df.loc[x]['vulnerable']==0]]
        if len(fixed):
            return fixed.loc[fixed.index[0]]['code']
        else:
            return None
    
    def get_shots(self, n, df, code, vulnerable=None, cwe=None, use_knn=False, fix=False, seed=None):
        """
        Sample the df for n distinct examples that belong to the vulnerability status and cwe, if specified.
        
        Args:
            n (int): Number of in-context examples to produce
            df (DataFrame): Input DataFrame in the format of the Copilot CWE Scenario dataset
            vulnerable (bool): If not None, filter shots for the given vulnerable status (default is None)
            cwe (str): If not None, filter shots for the given CWE (default is None)
            use_knn (bool): Take examples from "nearest neighbors" (i.e. samples with highest RougeL)
            fix (bool): Include non-vulnerable "fixed" code in shots
            seed (int): Set for reproducibility of random sampling

        Returns: List of tuples [(code_1, correct_answer_1), (code_2, correct_answer_2), ... ]
        """
        examples = []
        df_copy = df.copy(deep=True)

        # Filter the df for input criteria
        if vulnerable is True:
            df = df[df['vulnerable'] == 1]
        elif vulnerable is False:
            df = df[df['vulnerable'] == 0]
        if cwe is not None:
            df = df[df['cwe'] == cwe]
        
        if use_knn is False:
            shots = df.sample(n, random_state=seed)
        elif use_knn is True:
            # Compute RougeL scores between eligible examples and the input code
            scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=False)
            rouge_scores = [scorer.score(df.loc[i]['code'], code)['rougeL'].fmeasure for i in df.index]
            sorted_score_indices = np.argsort(rouge_scores)

            # Use examples with the highest RougeL scores
            i = 1  # Offset for index of largest rouge score
            top_indices = []
            used_scenarios = []
            while len(top_indices) < n and i <= len(sorted_score_indices):
                candidate_index = df.index[sorted_score_indices[-i]]
                candidate = df.loc[candidate_index]
                if candidate['scenario_id'] not in used_scenarios:
                    # If a fix is requested, ensure the candidate has one
                    if not fix or (fix and self._get_clean_example(candidate['scenario_id'], df_copy)):
                        top_indices.append(candidate_index)
                        used_scenarios.append(candidate['scenario_id'])
                i += 1

            assert len(top_indices) == n
            shots = df.loc[top_indices]

        if len(shots) == n:
            self.used_scenarios = []
            for i in range(n):
                self.used_scenarios.append(shots.loc[shots.index[i]]['scenario_id'])
                if shots.loc[shots.index[i]]['vulnerable'] == 1:
                    if not fix:
                        examples.append((shots.loc[shots.index[i]]['code'], '{{"label": "Vulnerable", "cwe": "{}"}}'.format(shots.loc[shots.index[i]]['cwe'])))
                    else:
                        fixed = self._get_clean_example(shots.loc[shots.index[i]]['scenario_id'], df_copy)
                        examples.append((shots.loc[shots.index[i]]['code'], '{{"label": "Vulnerable", "cwe": "{}", "fix": "```{}```"}}'.format(shots.loc[shots.index[i]]['cwe'], fixed)))
                else:
                    if not fix:
                        examples.append((shots.loc[shots.index[i]]['code'], '{{"label": "Not Vulnerable", "cwe": "None"}}'))
                    else:
                        examples.append((shots.loc[shots.index[i]]['code'], '{{"label": "Not Vulnerable", "cwe": "None", "fix": "None"}}'))
        else:
            raise Exception("Did not find {} examples with the desired criteria".format(n))

        self.shots = examples
        return examples