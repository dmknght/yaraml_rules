# Sophos AI YaraML Rules Repository
* This is a modified version attempt to collect metadata of ELF files using Rizin
*Questions, concerns, ideas, results, feedback appreciated, please email joshua.saxe@sophos.com*

YaraML is a tool that automatically generates Yara rules from training data by translating scikit-learn logistic regression and random forest binary classifiers into the Yara language.  Give YaraML a directory of malware files and a directory of benign files of any format and it'll extract substring features, downselect your feature space, train a model, and then "compile" the model and return it as a textual Yara rule.  To get a feel for what this looks like, see the logistic regression Powershell detector generated by YaraML and given below.

```
rule Generic_Powershell_Detector
{
strings:
...
$s4 = "DownloadFile"       fullword // weight: 3.257
$s5 = "WOW64"              fullword // weight: 3.232
$s6 = "bypass"             fullword // weight: 3.021
$s7 = "meMoRYSTrEaM"       fullword // weight: 2.68
$s8 = "obJEct"             fullword // weight: 2.679
$s9 = "OBJecT"             fullword // weight: 2.659
$s10 = "ReGeX"              fullword // weight: 2.592
$s11 = "samratashok"        fullword // weight: 2.548
$s12 = "Dependencies"       fullword // weight: 2.494
$s13 = "TVqQAAMAAAAEAAAA"   fullword // weight: 2.428
$s14 = "CompressionMode"    fullword // weight: 2.366
...
condition:
...
((#s0 * 5.567) + (#s1 * 4.122) + (#s2 * 3.904) + (#s3 * 3.820) + 
(#s4 * 3.257) + (#s5 * 3.232) + (#s6 * 3.021) + (#s7 * 2.680) + 
(#s8 * 2.679) + (#s9 * 2.659) + (#s10 * 2.592) + (#s11 * 2.548) + 
...
> 0
}
```

## How do I get started?

Clone this repo and install it by doing `python setup.py install` (please use Python 3.6 or above - this has been tested on OSX, Ubuntu and Redhat, your mileage may vary on Windows).  Invoke the tool as `yaraml`.

Here's an example invocation, assuming you have malicious Powershell scripts in *powershell_malware/* (or any of its subdirectories) and benign Powershell scripts in *powershell_benign/* (or any of its subdirectories):

```
yaraml powershell_malware/ powershell_benign/ # specify the malware and then benign directory in that order
powershell_model # specify the directory where we'll put the resulting rule
powershell_detector # specify the name of your Yara rule
--max_benign_files=100 --max_malicious_files=100 # you can optionally specify an upper bound on the number of files to train on
--model_type="logisticregression" # specify either logisticregression or randomforest here; will use sklearn default hyperparams
# N.B.; you can set hyperparams by using --model_instantiation instead of --model_type and calling the appropriate sklearn constructor:
# (--model_instantiation="LogisticRegression(penalty='l1',solver='liblinear')")
```

## Why YaraML?

Because sometimes we want to use ML models to do blue team work but only Yara is available.  And sometimes writing hand crafted rules is too time consuming, or we want an ML alternative to only trusting our rule-writing judgment.

## How well maintained is this code base?

We're providing research code here but will happily respond to questions and bug reports.  We want your feedback and we want to make this tool useful to the community.

## How do I cite YaraML?

@misc{Saxe2020,
  author = {Saxe, Joshua},
  title = {YaraML},
  year = {2020},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/sophos-ai/yaraml_rules/}}
}
