from ipywidgets import widgets
from prompt_utils import get_completion, ZeroShotPrompt, FewShotPrompt


class SecureCodeAssistant:
    """A Jupyter widget for detecting and fixing code vulnerabilities."""
    def __init__(self, df):
        self.df = df
        self.temperature = widgets.FloatSlider(
            value=0.6,
            max=1.0,
            step=0.01,
            description="Temperature")

        self.use_step_by_step = widgets.Checkbox(
            value=True,
            description='Use Step-by-Step',
            disabled=False,
            indent=False)

        self.use_knn = widgets.Checkbox(
            value=False,
            description='Use KNN',
            disabled=False,
            indent=False)

        self.num_shots = widgets.Dropdown(
            options=['0', '1', '2', '3'],
            value='3',
            description='Shots:',
            disabled=False,
        )

        self.input_code = widgets.Textarea(
            value='<insert code here>',
            placeholder='<insert code here>',
            description='Code:',
            disabled=False
        )

        self.output_options = widgets.SelectMultiple(
            options=['Detect Vulnerability', 'Generate Fix'],
            value=['Detect Vulnerability'],
            rows=3,
            description='Outputs',
            disabled=False
        )

        self.button = widgets.Button(
            description='Go',
            disabled=False,
            button_style='',
            tooltip='Go',
            icon='check'
        )

        self.output = widgets.Output(layout={'border': '1px solid black'})
        self.button.on_click(self.on_button_clicked)
        with self.output:
            print('---output will appear below---')
        
    def setup_ui(self):
        """Initializes widgets in a grid layout."""
        return widgets.HBox([
            widgets.VBox([self.input_code, self.temperature, self.num_shots, self.use_step_by_step, self.use_knn, self.button]),
            widgets.VBox([self.output_options, self.output])
            ])

    def on_button_clicked(self, b):
        """Clears output, queries the model, and populates output box with model's response."""
        self.output.clear_output()

        # Get shots
        n = int(self.num_shots.value)
        fix = 'Generate Fix' in self.output_options.value
        if n > 0:
            prompt_template = FewShotPrompt(step_by_step=self.use_step_by_step.value,
                                n=n, fix=fix)
        else:
            prompt_template = ZeroShotPrompt(step_by_step=self.use_step_by_step.value)
        
        shots = prompt_template.get_shots(n, self.df, self.input_code.value, 
                                          use_knn=self.use_knn.value, fix=fix)

        input_data = {}
        for i, shot in enumerate(shots): 
            input_data['example_{}'.format(i)] = shot[0]
            input_data['answer_{}'.format(i)] = shot[1]

        input_data['code'] = self.input_code.value
        
        prompt = prompt_template.get_prompt(input_data)
        response = get_completion(prompt)
        
        with self.output:
            print(response)
