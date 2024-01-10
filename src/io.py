import os

def write_to_output(context: dict[str, str]) -> None:
    """writes the keys (as variables) and values (as values) to the output buffer"""
    buffer_path = os.getenv("GITHUB_OUTPUT")

    if buffer_path == None:
        return

    with open(buffer_path, "a") as _buffer:
        for var, val in context.items():
            _buffer.write(f"{var}={val}\n")


def write_to_summary(line:str) -> None:
    """Display markdown content on the Actions run summary page"""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")

    if summary_path == None:
        print(line)
        return

    with open(summary_path, "a") as _summary:
        _summary.write(f'{line}\n')

def serialize_inputs() -> dict:
    """Encode input parameters into dictionary"""

    inputs = {}
    for name, value in os.environ.items():
        if 'INPUT' in name: 
            var_name = name.split("_", 1)[1]
            inputs[var_name.lower()] = value
    
    return inputs
