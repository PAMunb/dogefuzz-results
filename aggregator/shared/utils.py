def map_vulnerability_to_dogefuzz_standard(vulnerability: str) -> str:
    if vulnerability == 'delegatecall_dangerous':
        return 'delegate'
    elif vulnerability == 'exception_disorder':
        return 'exception-disorder'
    elif vulnerability == 'gassless_send':
        return 'gasless-send'
    elif vulnerability == 'numberdependency':
        return 'number-dependency'
    elif vulnerability == 'reentrancy':
        return 'reentrancy'
    elif vulnerability == 'timedependency':
        return 'timestamp-dependency'
    else:
        return None
