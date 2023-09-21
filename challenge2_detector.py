"""
This is a basic slither detector template.

Some basic setup:

Make a `custom` folder to hold your detectors in the slither project, such as
- `<path/to/slither>/slither/detectors/custom/`
- add a `__init__.py` file to this folder
this is where you will place your detector files

Place this file in the `custom` folder, and rename it to your detector name.

Add the following line to `<path/to/slither>/slither/detectors/all_detectors.py`:
    from .custom.hello_world import HelloWorld

Run slither with your detector:
    slither . --detect hello_world

"""

from typing import List
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output
from slither.core.variables.state_variable import StateVariable


class Challenge2(AbstractDetector):
    """
    Find contracts that have a "hello_world" function
    """

    # shows up in `slither --list-detectors`
    ARGUMENT = "challenge2_detector"  # run with `slither . --detect <ARGUMENT>`
    HELP = "Find contracts that have a hello_world function"
    # HIGH, MEDIUM, LOW, INFORMATIONAL, OPTIMIZATION
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH  # HIGH, MEDIUM, LOW

    # These wiki values are required, but I typically leave them as "."
    WIKI = (".")
    WIKI_TITLE = "."
    WIKI_DESCRIPTION = "."
    WIKI_EXPLOIT_SCENARIO = "."
    WIKI_RECOMMENDATION = "."

    def _detect(self) -> List[Output]:
        results = []
        for c in self.contracts:
            for f in c.functions:
                for node in f.nodes:
                    for ir in node.irs:
                        for var in ir.read:
                            if isinstance(var, StateVariable):
                                if var.visibility == "private":
                                    info: DETECTOR_INFO = [
                                        f,
                                        " reveals private var ",
                                        var,
                                        " of ",
                                        c,
                                        "\n",
                                    ]
                                    json = self.generate_result(info)

                                    results.append(json)
        return results
