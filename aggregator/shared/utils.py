def map_vulnerability_to_dogefuzz_standard(vulnerability: str) -> str:
    if vulnerability == 'delegatecall_dangerous':
        return 'delegate'
    elif vulnerability == 'exception_disorder':
        return 'exception-disorder'
    elif vulnerability == 'gasless_send':
        return 'gasless-send'
    elif vulnerability == 'numberdependency':
        return 'number-dependency'
    elif vulnerability == 'reentrancy':
        return 'reentrancy'
    elif vulnerability == 'timedependency':
        return 'timestamp-dependency'
    else:
        return None


def map_vulnerability_to_smartian_standard(vulnerability: str) -> str:
    if vulnerability == 'delegatecall_dangerous':
        return 'ME'
    elif vulnerability == 'exception_disorder':
        return 'ME'
    elif vulnerability == 'gasless_send':
        return 'ME'
    elif vulnerability == 'numberdependency':
        return 'BD'
    elif vulnerability == 'reentrancy':
        return 'RE'
    elif vulnerability == 'timedependency':
        return 'BD'
    else:
        return None


def map_weakness_to_smartian_standard(vulnerability: str) -> str:
    if vulnerability == 'delegate':
        return 'ME'
    elif vulnerability == 'exception-disorder':
        return 'ME'
    elif vulnerability == 'gasless-send':
        return 'ME'
    elif vulnerability == 'number-dependency':
        return 'BD'
    elif vulnerability == 'reentrancy':
        return 'RE'
    elif vulnerability == 'timestamp-dependency':
        return 'BD'
    else:
        return None
