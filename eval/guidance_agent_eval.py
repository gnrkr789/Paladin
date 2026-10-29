"""Score candidate-guidance agent edits without treating missing data as success."""


def assess_attempt(host_exit, source_changed, unexpected_files, assessments):
    """Return success, failed, or incomplete for one isolated agent attempt."""
    if (host_exit != 0 or not source_changed or unexpected_files or assessments is None
            or not assessments or {case["role"] for case in assessments} != {"risk", "safe"}):
        return "incomplete"
    return "success" if all(case["pass"] for case in assessments) else "failed"
