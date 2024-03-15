import json
import matplotlib.pyplot as plt
import numpy as np
from rouge_score import rouge_scorer
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


def get_predictions(results, verbose=False):
    """Read a list of json responses and create a list of True/False predictions."""
    y_pred = []
    for r in results:
        if r is not None:
            if 'Not Vulnerable' in r:
                vulnerable = False
            else:
                vulnerable = True
            if verbose:
                print('{} translates to {}'.format(r, vulnerable))
            y_pred.append(vulnerable)

    return y_pred

def get_and_display_metrics(y_true, y_pred):
    """Print classification metrics and a confusion matrix."""
    report = classification_report(y_true, y_pred)
    print(report)

    metrics = {'Accuracy': accuracy_score(y_true, y_pred),
               'Precision': precision_score(y_true, y_pred),
               'Recall': recall_score(y_true, y_pred),
               'F1': f1_score(y_true, y_pred)}
    print('Accuracy: {Accuracy}\nPrecision: {Precision}\nRecall: {Recall}\nF1 Score: {F1}'.format(**metrics))

    cm = confusion_matrix(y_true, y_pred)
    cmd = ConfusionMatrixDisplay(cm, display_labels=['Not Vulnerable', 'Vulnerable'])
    cmd.plot()

    return metrics

def get_fixes(results):
    """Parse and return only the fixed code snippets from a list of json responses."""
    fixes = []
    for result in results:
        if ', "fix": "```' in result:
            fixes.append(result.split(', "fix": "```', 1)[1].split('```')[0])
        else:
            fixes.append(None)

    return fixes

def make_chart(metrics):
    """Print a bar chart from metrics dictionary."""
    prompt_types = metrics.keys()
    display_metrics = {
        'Accuracy': [round(100*metrics[k]['Accuracy'], 1) for k in prompt_types],
        'Precision': [round(100*metrics[k]['Precision'], 1) for k in prompt_types],
        'Recall': [round(100*metrics[k]['Recall'], 1) for k in prompt_types],
        'F1': [round(100*metrics[k]['F1'], 1) for k in prompt_types],
    }

    x = np.arange(len(prompt_types))  # the label locations
    width = 0.20  # the width of the bars
    multiplier = 0

    fig, ax = plt.subplots(layout='constrained', figsize=(10, 6))

    for attribute, measurement in display_metrics.items():
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute)
        ax.bar_label(rects, padding=3)
        multiplier += 1

    # Add labels, title, custom x-axis tick labels, and legend
    ax.set_ylabel('Percentage')
    ax.set_title('Performance by Prompt')
    ax.set_xticks(x + width, prompt_types)
    ax.legend(loc='upper left', ncols=4)
    
    plt.ylim((0, 110))
    plt.show()